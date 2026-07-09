package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/locktivity/epack-collector-documents/internal/locktivity"
	"github.com/locktivity/epack/componentsdk"
)

// Run-key priority: explicit config, the CI's exported per-run key, the
// GitHub Actions run identity, then a fresh random key.
func TestResolveRunKey(t *testing.T) {
	secrets := func(values map[string]string) func(string) string {
		return func(key string) string { return values[key] }
	}

	if got := resolveRunKey(map[string]any{"run_key": "pinned"}, secrets(map[string]string{"LOCKTIVITY_RUN_KEY": "ci-9"})); got != "pinned" {
		t.Errorf("config run_key should win, got %q", got)
	}
	if got := resolveRunKey(nil, secrets(map[string]string{"LOCKTIVITY_RUN_KEY": "ci-9", "GITHUB_RUN_ID": "42"})); got != "ci-9" {
		t.Errorf("LOCKTIVITY_RUN_KEY should beat the GitHub fallback, got %q", got)
	}
	if got := resolveRunKey(nil, secrets(map[string]string{"GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "2"})); got != "gha-42-2" {
		t.Errorf("GitHub identity fallback wrong: %q", got)
	}
	if got := resolveRunKey(nil, secrets(map[string]string{"GITHUB_RUN_ID": "42"})); got != "gha-42-1" {
		t.Errorf("missing attempt should default to 1, got %q", got)
	}
	if got := resolveRunKey(nil, secrets(nil)); !strings.HasPrefix(got, "local-") {
		t.Errorf("expected random local key, got %q", got)
	}
}

// A custom endpoint must not blanket-disable download SSRF checks: only a
// dev-tagged plain HTTP loopback endpoint relaxes them. HTTPS endpoints, even
// loopback staging overrides, stay strict.
func TestAllowInsecureDownloadsForEndpoint(t *testing.T) {
	wantLocalHTTP := locktivity.PlainHTTPLoopbackDevBuilds()
	cases := map[string]bool{
		"":                         false,
		"http://127.0.0.1:3000":    wantLocalHTTP,
		"http://[::1]:3000":        wantLocalHTTP,
		"http://localhost:3000":    wantLocalHTTP,
		"https://127.0.0.1:3000":   false,
		"http://10.0.0.1:3000":     false,
		"http://93.184.216.34/x":   false,
		"https://93.184.216.34/x":  false,
		"https://api.locktivity/x": false,
	}
	for endpoint, want := range cases {
		if got := locktivity.AllowInsecureDownloadsForEndpoint(endpoint); got != want {
			t.Errorf("AllowInsecureDownloadsForEndpoint(%q) = %v, want %v", endpoint, got, want)
		}
	}
}

func TestRunRequiresStagingBeforeAuth(t *testing.T) {
	err := run(noStagingContext{})
	if err == nil {
		t.Fatal("run returned nil")
	}

	var configErr componentsdk.ConfigError
	if !errors.As(err, &configErr) {
		t.Fatalf("run error = %T, want ConfigError", err)
	}

	var authErr componentsdk.AuthError
	if errors.As(err, &authErr) {
		t.Fatalf("run error = %T, want staging ConfigError before auth", err)
	}
}

type noStagingContext struct{}

func (noStagingContext) Context() context.Context { return context.Background() }
func (noStagingContext) Name() string             { return "documents" }
func (noStagingContext) Config() map[string]any   { return nil }
func (noStagingContext) Level() componentsdk.Level {
	return componentsdk.LevelTrust
}
func (noStagingContext) Secret(string) string { return "" }
func (noStagingContext) Status(string)        {}
func (noStagingContext) Progress(int64, int64, string) {
}
func (noStagingContext) Emit([]componentsdk.CollectedArtifact) error {
	return nil
}
