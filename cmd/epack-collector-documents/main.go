package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/locktivity/epack-collector-documents/internal/collector"
	"github.com/locktivity/epack-collector-documents/internal/limits"
	"github.com/locktivity/epack-collector-documents/internal/locktivity"
	"github.com/locktivity/epack/componentsdk"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

const (
	configPipelineID       = "pipeline_id"
	configRunKey           = "run_key"
	configEndpoint         = "insecure_endpoint"
	configAuthEndpoint     = "insecure_auth_endpoint"
	secretDocumentsToken   = "LOCKTIVITY_DOCUMENTS_TOKEN"
	secretClientID         = "LOCKTIVITY_CLIENT_ID"
	secretClientSecret     = "LOCKTIVITY_CLIENT_SECRET"
	secretRunKey           = "LOCKTIVITY_RUN_KEY"
	secretGitHubRunID      = "GITHUB_RUN_ID"
	secretGitHubRunAttempt = "GITHUB_RUN_ATTEMPT"
)

type runtimeConfig struct {
	PipelineID string
	Token      string
	RunKey     string
	Endpoint   locktivity.EndpointPolicy
}

func main() {
	componentsdk.RunCollector(componentsdk.CollectorSpec{
		Name:        "documents",
		Version:     Version,
		Commit:      Commit,
		Description: "Includes the account's evidence documents in packs",
		Timeout:     limits.CollectorTimeout,
	}, run)
}

func run(ctx componentsdk.CollectorContext) error {
	staging, ok := componentsdk.Staging(ctx)
	if !ok || staging.OutputDir() == "" {
		return componentsdk.NewConfigError("this collector stages document files and requires an epack version that sets EPACK_COLLECTOR_OUTPUT_DIR; upgrade epack")
	}

	runtime, err := loadRuntimeConfig(ctx)
	if err != nil {
		return err
	}

	client := locktivity.NewClient(runtime.Endpoint.BaseURL, runtime.Token, Version)
	output, err := collector.Collect(ctx.Context(), collector.Config{
		PipelineID: runtime.PipelineID,
		RunKey:     runtime.RunKey,
		Stager:     staging,
		OnStatus:   ctx.Status,
		OnProgress: ctx.Progress,
	}, client)
	if err != nil {
		return classifyCollectError(err)
	}

	return ctx.Emit(collectedArtifacts(output))
}

func loadRuntimeConfig(ctx componentsdk.CollectorContext) (runtimeConfig, error) {
	cfg := ctx.Config()
	pipelineID := getString(cfg, configPipelineID)
	token, err := resolveToken(ctx, cfg, pipelineID)
	if err != nil {
		return runtimeConfig{}, err
	}

	endpointRaw := getString(cfg, configEndpoint)
	endpoint, err := locktivity.ResolveEndpointPolicy("endpoint", endpointRaw)
	if err != nil {
		return runtimeConfig{}, componentsdk.NewConfigError("%v", err)
	}
	if endpoint.BaseURL != "" {
		fmt.Fprintf(os.Stderr, "warning: using custom endpoint %s\n", endpoint.BaseURL)
	}

	return runtimeConfig{
		PipelineID: pipelineID,
		Token:      token,
		RunKey:     resolveRunKey(cfg, ctx.Secret),
		Endpoint:   endpoint,
	}, nil
}

func classifyCollectError(err error) error {
	var configErr locktivity.ConfigError
	switch {
	case errors.Is(err, locktivity.ErrUnauthorized):
		return componentsdk.NewAuthError("%v", err)
	case errors.As(err, &configErr):
		return componentsdk.NewConfigError("%v", err)
	default:
		return componentsdk.NewNetworkError("collecting documents: %v", err)
	}
}

func collectedArtifacts(output *collector.Output) []componentsdk.CollectedArtifact {
	artifacts := []componentsdk.CollectedArtifact{
		componentsdk.JSONArtifact(collector.DocumentIndexPackPath, output.Index, componentsdk.ArtifactMeta{
			Schema:      collector.DocumentIndexSchema,
			DisplayName: "Documents index",
			Description: "The documents included in this pack, with a pointer to each.",
		}),
	}
	for _, file := range output.Files {
		artifacts = append(artifacts, componentsdk.FileArtifact(file.PackPath, file.RelPath, componentsdk.ArtifactMeta{
			DisplayName: file.DisplayName,
			Schema:      file.Schema,
		}))
	}
	for _, metadata := range output.Metadata {
		artifacts = append(artifacts, componentsdk.JSONArtifact(metadata.PackPath, metadata.Body, componentsdk.ArtifactMeta{
			Schema:      metadata.Schema,
			DisplayName: metadata.DisplayName,
		}))
	}
	return artifacts
}

func resolveToken(ctx componentsdk.CollectorContext, cfg map[string]any, pipelineID string) (string, error) {
	if token := ctx.Secret(secretDocumentsToken); token != "" {
		return token, nil
	}

	clientID := ctx.Secret(secretClientID)
	clientSecret := ctx.Secret(secretClientSecret)
	if clientID == "" || clientSecret == "" {
		return "", componentsdk.NewAuthError("no credentials: provide the brokered LOCKTIVITY_DOCUMENTS_TOKEN, or LOCKTIVITY_CLIENT_ID and LOCKTIVITY_CLIENT_SECRET from an API application")
	}
	if pipelineID == "" {
		return "", componentsdk.NewConfigError("pipeline_id is required when authenticating with client credentials")
	}

	authEndpoint := getString(cfg, configAuthEndpoint)
	if authEndpoint != "" {
		fmt.Fprintf(os.Stderr, "warning: using custom auth endpoint %s\n", authEndpoint)
	}
	token, err := locktivity.ExchangeClientCredentials(ctx.Context(), authEndpoint, clientID, clientSecret)
	if err != nil {
		return "", componentsdk.NewAuthError("exchanging client credentials: %v", err)
	}
	return token, nil
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
