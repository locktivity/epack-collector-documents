package collector

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-documents/internal/locktivity"
	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
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

func TestRunRequiresStagingBeforeAuth(t *testing.T) {
	res := componentsdk.RunInProcess(Spec("test", "test"), Run, componentsdk.InProcessOptions{
		Secrets:   map[string]string{locktivity.EnvDocumentsToken: kitToken},
		Transport: replay(t, kitResponses(kitLibrary())...),
	})
	if res.ExitCode != 2 || res.Failure == nil || res.Failure.Code != componentsdk.CodeConfigInvalid {
		t.Fatalf("exit %d, failure %+v; want exit 2 with config_invalid", res.ExitCode, res.Failure)
	}
	if res.Result != nil {
		t.Fatalf("a run without staging made calls: %+v", res.Result.Calls)
	}
}

func TestRunFailsOnInvalidConfiguration(t *testing.T) {
	clientCredentials := map[string]string{locktivity.EnvClientID: kitClientID, locktivity.EnvClientSecret: kitClientSecret}
	cases := []struct {
		name    string
		config  map[string]any
		secrets map[string]string
	}{
		{"no credentials", map[string]any{configPipelineID: kitPipelineID}, nil},
		{"client id without secret", map[string]any{configPipelineID: kitPipelineID}, map[string]string{locktivity.EnvClientID: kitClientID}},
		{"client credentials without pipeline_id", nil, clientCredentials},
		{"plain HTTP endpoint", map[string]any{configEndpoint: "http://192.0.2.10:3000"}, map[string]string{locktivity.EnvDocumentsToken: kitToken}},
		{"plain HTTP auth endpoint", map[string]any{configPipelineID: kitPipelineID, configAuthEndpoint: "http://192.0.2.10:9"}, clientCredentials},
		{"endpoint with credentials", map[string]any{configEndpoint: "https://user:pass@api.example.test"}, map[string]string{locktivity.EnvDocumentsToken: kitToken}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			transport := replay(t)
			res := runInProcess(t, tc.config, tc.secrets, transport)
			if res.ExitCode != 2 || res.Failure == nil || res.Failure.Code != componentsdk.CodeConfigInvalid {
				t.Fatalf("exit %d, failure %+v; want exit 2 with config_invalid", res.ExitCode, res.Failure)
			}
			if sent := transport.Unmatched(); len(sent) > 0 {
				t.Errorf("an invalid configuration sent requests: %v", sent)
			}
		})
	}
}

func TestRunFailsWhenSignInFails(t *testing.T) {
	clientCredentials := map[string]string{locktivity.EnvClientID: kitClientID, locktivity.EnvClientSecret: kitClientSecret}
	config := map[string]any{configPipelineID: kitPipelineID, configRunKey: kitRunKey}
	token := func(status int, body string) http.RoundTripper {
		return replay(t, collectortest.Response{Method: http.MethodPost, URL: kitTokenURL, Status: status, Body: body})
	}
	cases := []struct {
		name      string
		secrets   map[string]string
		transport http.RoundTripper
		code      componentsdk.Code
		exit      int
	}{
		{"brokered token rejected", map[string]string{locktivity.EnvDocumentsToken: kitToken},
			replay(t, collectortest.Response{Method: http.MethodPost, URL: kitSnapshotURL, Status: 401, Body: `{"errors":["Unauthorized"],"code":"UNAUTHORIZED"}`}),
			componentsdk.CodeAuthFailed, 3},
		{"token lacks the snapshot scope", map[string]string{locktivity.EnvDocumentsToken: kitToken},
			replay(t, collectortest.Response{Method: http.MethodPost, URL: kitSnapshotURL, Status: 403, Body: `{"errors":["Insufficient scope"],"code":"INSUFFICIENT_SCOPE"}`}),
			componentsdk.CodePermissionDenied, 3},
		{"pipeline without the Documents collector", map[string]string{locktivity.EnvDocumentsToken: kitToken},
			replay(t, collectortest.Response{Method: http.MethodPost, URL: kitSnapshotURL, Status: 422, Body: `{"errors":["Pipeline has no documents collector"],"code":"VALIDATION_ERROR"}`}),
			componentsdk.CodeConfigInvalid, 2},
		{"client rejected", clientCredentials, token(401, `{"error":"invalid_client"}`), componentsdk.CodeAuthFailed, 3},
		{"grant rejected", clientCredentials, token(400, `{"error":"invalid_grant"}`), componentsdk.CodeAuthFailed, 3},
		{"scope not granted", clientCredentials, token(400, `{"error":"invalid_scope"}`), componentsdk.CodePermissionDenied, 3},
		{"token endpoint unavailable", clientCredentials, token(503, `Service Unavailable`), componentsdk.CodeVendorError, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runInProcess(t, config, tc.secrets, tc.transport)
			if res.ExitCode != tc.exit || res.Failure == nil || res.Failure.Code != tc.code {
				t.Fatalf("exit %d, failure %+v; want exit %d with %s", res.ExitCode, res.Failure, tc.exit, tc.code)
			}
		})
	}
}

func TestRunLeavesOutADocumentItCannotDownload(t *testing.T) {
	responses := kitResponses(kitLibrary())
	failing := kitLibrary()[1].downloadURL("source")
	for i := range responses {
		if responses[i].URL == failing {
			responses[i].Status = http.StatusInternalServerError
			responses[i].Body = `<Error><Code>InternalError</Code></Error>`
		}
	}
	outputDir := t.TempDir()
	res := runInProcessIn(t, outputDir, map[string]any{configRunKey: kitRunKey}, map[string]string{locktivity.EnvDocumentsToken: kitToken}, replay(t, responses...))
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}

	index := emittedIndex(t, res)
	left := index.Documents[1]
	if left.Name != "Access control policy" || left.DocumentType == nil {
		t.Fatalf("the left-out document should keep its identity, got %+v", left)
	}
	for _, field := range []string{"file", "source_file", "text", "metadata"} {
		if _, ok := left.raw[field]; ok {
			t.Errorf("left-out document still has %s: %s", field, left.raw[field])
		}
	}

	want := map[string]bool{
		DocumentIndexPackPath + " /documents/1/file":           true,
		DocumentIndexPackPath + " /documents/1/source_file":    true,
		DocumentIndexPackPath + " /documents/1/text":           true,
		DocumentIndexPackPath + " /documents/1/metadata":       true,
		"artifacts/documents/doc_2/access-control-policy.pdf ": true,
		"artifacts/documents/doc_2/access-control-policy.md ":  true,
		"artifacts/documents/doc_2/text.json ":                 true,
		"artifacts/documents/doc_2/metadata.json ":             true,
	}
	for _, gap := range res.Result.Gaps {
		key := gap.Path + " " + gap.Pointer
		if !want[key] {
			t.Errorf("unexpected gap %s", key)
			continue
		}
		delete(want, key)
		if gap.Code != componentsdk.CodeVendorError || gap.Status != componentsdk.GapNotCollected {
			t.Errorf("gap %s = %s %s, want not_collected vendor_error", key, gap.Status, gap.Code)
		}
	}
	for key := range want {
		t.Errorf("missing gap %s", key)
	}
	if res.Result.Outcome.Status != componentsdk.OutcomePartial {
		t.Errorf("outcome = %+v, want partial", res.Result.Outcome)
	}

	emitted := map[string]bool{}
	for _, a := range res.Artifacts {
		emitted[a.Path] = true
	}
	for _, path := range []string{
		"artifacts/documents/doc_1/acme-soc2-2025.pdf", "artifacts/documents/doc_1/text.json", "artifacts/documents/doc_1/metadata.json",
		"artifacts/documents/doc_3/vendor-inventory.xlsx", "artifacts/documents/doc_5/data-retention-policy.docx",
	} {
		if !emitted[path] {
			t.Errorf("%s was not emitted", path)
		}
	}
	for path := range emitted {
		if strings.Contains(path, "doc_2") {
			t.Errorf("left-out document's %s was emitted", path)
		}
	}
	if _, err := os.Stat(filepath.Join(outputDir, "documents/doc_2/access-control-policy.pdf")); !os.IsNotExist(err) {
		t.Errorf("the left-out document's downloaded file should be removed from staging, stat err=%v", err)
	}
}

func TestRunRecordsADocumentWithNoFileInTheIndex(t *testing.T) {
	res := runInProcessIn(t, t.TempDir(), map[string]any{configRunKey: kitRunKey}, map[string]string{locktivity.EnvDocumentsToken: kitToken}, replay(t, kitResponses(kitLibrary())...))
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	if len(res.Result.Gaps) != 0 || len(res.Result.Checks) != 0 {
		t.Fatalf("clean run left gaps %+v and checks %+v", res.Result.Gaps, res.Result.Checks)
	}
	entry := emittedIndex(t, res).Documents[3]
	for _, field := range []string{"version_number", "document_type", "file", "source_file", "text", "metadata"} {
		if raw, ok := entry.raw[field]; !ok || string(raw) != "null" {
			t.Errorf("%s = %s, want null for a document with no file", field, raw)
		}
	}
	if len(entry.Warnings) != 1 {
		t.Errorf("warnings = %v, want the snapshot's warning", entry.Warnings)
	}
}

func TestRunRecordsTheSignedInPrincipal(t *testing.T) {
	cases := []struct {
		name      string
		config    map[string]any
		secrets   map[string]string
		responses []collectortest.Response
		want      componentsdk.Principal
	}{
		{
			name: "brokered token", config: map[string]any{configRunKey: kitRunKey},
			secrets:   map[string]string{locktivity.EnvDocumentsToken: kitToken},
			responses: kitResponses(kitLibrary()),
			want:      componentsdk.Principal{Provider: "locktivity", Kind: "pipeline_token"},
		},
		{
			name: "client credentials", config: map[string]any{configRunKey: kitRunKey, configPipelineID: kitPipelineID},
			secrets:   map[string]string{locktivity.EnvClientID: kitClientID, locktivity.EnvClientSecret: kitClientSecret},
			responses: append([]collectortest.Response{kitTokenResponse()}, kitResponses(kitLibrary())...),
			want:      componentsdk.Principal{Provider: "locktivity", Kind: "api_application", Scopes: []string{"write:document_snapshots"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runInProcessIn(t, t.TempDir(), tc.config, tc.secrets, replay(t, tc.responses...))
			if res.ExitCode != 0 || res.Result == nil {
				t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
			}
			if !reflect.DeepEqual(res.Result.SignedInAs, &tc.want) {
				t.Errorf("signed_in_as = %+v, want %+v", res.Result.SignedInAs, tc.want)
			}
		})
	}
}

// indexEntryJSON is an emitted index entry, with its raw fields to tell an
// absent field from a null one.
type indexEntryJSON struct {
	Name         string   `json:"name"`
	DocumentType *string  `json:"document_type"`
	Warnings     []string `json:"warnings"`
	raw          map[string]json.RawMessage
}

type indexJSON struct {
	Documents []indexEntryJSON
}

func emittedIndex(t *testing.T, res componentsdk.InProcessResult) indexJSON {
	t.Helper()
	for _, a := range res.Artifacts {
		if a.Path != DocumentIndexPackPath {
			continue
		}
		var docs struct {
			Documents []json.RawMessage `json:"documents"`
		}
		if err := json.Unmarshal(a.Data, &docs); err != nil {
			t.Fatal(err)
		}
		var index indexJSON
		for _, raw := range docs.Documents {
			var entry indexEntryJSON
			if err := json.Unmarshal(raw, &entry); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &entry.raw); err != nil {
				t.Fatal(err)
			}
			index.Documents = append(index.Documents, entry)
		}
		return index
	}
	t.Fatalf("no %s in %+v", DocumentIndexPackPath, res.Artifacts)
	return indexJSON{}
}

// runInProcess runs the collector in process with a fresh staging directory.
func runInProcess(t *testing.T, config map[string]any, secrets map[string]string, transport http.RoundTripper) componentsdk.InProcessResult {
	t.Helper()
	return runInProcessIn(t, t.TempDir(), config, secrets, transport)
}

func runInProcessIn(t *testing.T, outputDir string, config map[string]any, secrets map[string]string, transport http.RoundTripper) componentsdk.InProcessResult {
	t.Helper()
	return componentsdk.RunInProcess(Spec("test", "test"), Run, componentsdk.InProcessOptions{
		Config:    config,
		Secrets:   secrets,
		Transport: transport,
		OutputDir: outputDir,
		Seed:      1,
		Sleep:     func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
	})
}

// replay answers a run's requests from responses, as the kit's runs do, and
// a request none matches with a 404.
func replay(t *testing.T, responses ...collectortest.Response) *collectortest.Replay {
	t.Helper()
	r, err := collectortest.NewReplay(collectortest.Scenario{Responses: responses})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
