package collector

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/locktivity/epack-collector-documents/docs/schema"
	"github.com/locktivity/epack-collector-documents/internal/limits"
	"github.com/locktivity/epack-collector-documents/internal/locktivity"
	"github.com/locktivity/epack/componentsdk"
)

const (
	configPipelineID       = "pipeline_id"
	configRunKey           = "run_key"
	configEndpoint         = "insecure_endpoint"
	configAuthEndpoint     = "insecure_auth_endpoint"
	secretRunKey           = "LOCKTIVITY_RUN_KEY"
	secretGitHubRunID      = "GITHUB_RUN_ID"
	secretGitHubRunAttempt = "GITHUB_RUN_ATTEMPT"
)

// Spec describes the collector to componentsdk.RunCollector.
func Spec(version, commit string) componentsdk.CollectorSpec {
	return componentsdk.CollectorSpec{
		Name:        collectorName,
		Version:     version,
		Commit:      commit,
		Description: "Includes the account's evidence documents in packs",
		Timeout:     limits.CollectorTimeout,
		Schemas:     schema.Schemas(),
		TraceMap:    schema.TraceMap,
		// A metadata file's schema ID is its document's type in Locktivity,
		// so Writes lists only the index and text schemas.
		Writes: []string{DocumentIndexSchema, DocumentTextSchema},
	}
}

// Run is the collector's handler. It fails for invalid configuration, a
// failed sign-in, or a snapshot it cannot take, and otherwise emits every
// document it could download and verify, with a gap recorded for each one it
// left out.
func Run(ctx componentsdk.CollectorContext) error {
	staging, ok := componentsdk.Staging(ctx)
	if !ok || staging.OutputDir() == "" {
		return componentsdk.NewConfigError("this collector stages document files and requires an epack version that sets EPACK_COLLECTOR_OUTPUT_DIR; upgrade epack")
	}

	cfg, err := loadConfig(ctx)
	if err != nil {
		return err
	}
	token, principal, err := signIn(ctx, cfg)
	if err != nil {
		return err
	}

	rec := componentsdk.Records(ctx)
	output, err := Collect(ctx.Context(), Config{
		PipelineID: cfg.pipelineID,
		RunKey:     cfg.runKey,
		Stager:     staging,
		Recorder:   rec,
		Name:       ctx.Name(),
		OnStatus:   ctx.Status,
		OnProgress: ctx.Progress,
	}, locktivity.NewClient(ctx, cfg.endpoint, token))
	if err != nil {
		return err
	}
	rec.SignedInAs(principal)
	return ctx.Emit(output.Artifacts())
}

type runConfig struct {
	pipelineID   string
	runKey       string
	endpoint     string
	authEndpoint string
}

func loadConfig(ctx componentsdk.CollectorContext) (runConfig, error) {
	cfg := ctx.Config()
	endpoint, err := locktivity.ResolveEndpointPolicy(configEndpoint, getString(cfg, configEndpoint))
	if err != nil {
		return runConfig{}, componentsdk.NewConfigError("%v", err)
	}
	if endpoint.BaseURL != "" {
		fmt.Fprintf(os.Stderr, "warning: using custom endpoint %s\n", endpoint.BaseURL)
	}
	return runConfig{
		pipelineID:   getString(cfg, configPipelineID),
		runKey:       resolveRunKey(cfg, ctx.Secret),
		endpoint:     endpoint.BaseURL,
		authEndpoint: getString(cfg, configAuthEndpoint),
	}, nil
}

// signIn returns the token the API calls carry and the principal it stands
// for: the token Locktivity brokered for the run, or one minted from an API
// application's client credentials.
func signIn(ctx componentsdk.CollectorContext, cfg runConfig) (string, componentsdk.Principal, error) {
	if token := ctx.Secret(locktivity.EnvDocumentsToken); token != "" {
		return token, componentsdk.Principal{Provider: "locktivity", Kind: "pipeline_token"}, nil
	}

	clientID := ctx.Secret(locktivity.EnvClientID)
	clientSecret := ctx.Secret(locktivity.EnvClientSecret)
	if clientID == "" || clientSecret == "" {
		return "", componentsdk.Principal{}, componentsdk.NewConfigError("no credentials: provide the brokered %s, or %s and %s from an API application",
			locktivity.EnvDocumentsToken, locktivity.EnvClientID, locktivity.EnvClientSecret)
	}
	if cfg.pipelineID == "" {
		return "", componentsdk.Principal{}, componentsdk.NewConfigError("pipeline_id is required when authenticating with client credentials")
	}

	if cfg.authEndpoint != "" {
		fmt.Fprintf(os.Stderr, "warning: using custom auth endpoint %s\n", cfg.authEndpoint)
	}
	token, err := locktivity.ExchangeClientCredentials(ctx, cfg.authEndpoint, clientID, clientSecret)
	if err != nil {
		return "", componentsdk.Principal{}, fmt.Errorf("exchanging client credentials: %w", err)
	}
	return token.AccessToken, componentsdk.Principal{Provider: "locktivity", Kind: "api_application", Scopes: token.Scopes}, nil
}

func resolveRunKey(cfg map[string]any, secret func(string) string) string {
	if key := getString(cfg, configRunKey); key != "" {
		return key
	}
	if key := secret(secretRunKey); key != "" {
		return key
	}
	if runID := secret(secretGitHubRunID); runID != "" {
		attempt := secret(secretGitHubRunAttempt)
		if attempt == "" {
			attempt = "1"
		}
		return "gha-" + runID + "-" + attempt
	}
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return "local-" + hex.EncodeToString(buf)
}

func getString(cfg map[string]any, key string) string {
	if cfg == nil {
		return ""
	}
	if v, ok := cfg[key].(string); ok {
		return v
	}
	return ""
}
