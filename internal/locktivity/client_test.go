package locktivity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCreateSnapshot(t *testing.T) {
	var gotAuth, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/management/v1/evidence_packs/document_snapshots" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		gotBody = body.String()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "snap-1",
			"run_key": "gha-42-1",
			"digest":  "abc",
			"documents": []map[string]any{
				{"document_id": "doc-1", "name": "Policy", "artifact_path": "documents/policy.pdf", "file_url": "https://files.example/x"},
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "token-123", "test", false)
	snapshot, err := client.CreateSnapshot(context.Background(), "", "gha-42-1")
	if err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	if gotAuth != "Bearer token-123" {
		t.Errorf("unexpected auth header: %s", gotAuth)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil || body["run_key"] != "gha-42-1" || len(body) != 1 {
		t.Errorf("unexpected request body: %s", gotBody)
	}

	if _, err := client.CreateSnapshot(context.Background(), "pl_9f8e7d", "run-2"); err != nil {
		t.Fatalf("CreateSnapshot with pipeline failed: %v", err)
	}
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil || body["pipeline_id"] != "pl_9f8e7d" || body["run_key"] != "run-2" {
		t.Errorf("unexpected request body with pipeline: %s", gotBody)
	}
	if snapshot.ID != "snap-1" || len(snapshot.Documents) != 1 || snapshot.Documents[0].FileURL == "" {
		t.Errorf("unexpected snapshot: %+v", snapshot)
	}
}

func TestCreateSnapshotAuthError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	_, err := NewClient(server.URL, "bad", "test", false).CreateSnapshot(context.Background(), "", "run-1")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestCreateSnapshotConfigError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"errors":["Pipeline has no documents collector"]}`))
	}))
	defer server.Close()

	_, err := NewClient(server.URL, "token", "test", false).CreateSnapshot(context.Background(), "", "run-1")
	var configErr ConfigError
	if !errors.As(err, &configErr) {
		t.Fatalf("expected ConfigError, got %v", err)
	}
	if configErr.Message != "Pipeline has no documents collector" {
		t.Errorf("unexpected message: %s", configErr.Message)
	}
}

func TestCreateSnapshotRetriesServerErrors(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "snap-1"})
	}))
	defer server.Close()

	snapshot, err := NewClient(server.URL, "token", "test", false).CreateSnapshot(context.Background(), "", "run-1")
	if err != nil {
		t.Fatalf("CreateSnapshot failed after retries: %v", err)
	}
	if attempts != 3 || snapshot.ID != "snap-1" {
		t.Errorf("expected success on third attempt, attempts=%d snapshot=%+v", attempts, snapshot)
	}
}

func TestDownload(t *testing.T) {
	content := []byte("%PDF-1.4 downloaded content")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("pre-signed downloads must not carry the API token")
		}
		_, _ = w.Write(content)
	}))
	defer server.Close()

	var buf bytes.Buffer
	digest, n, err := NewClient(server.URL, "token", "test", true).Download(context.Background(), server.URL, &buf)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	expected := sha256.Sum256(content)
	if digest != hex.EncodeToString(expected[:]) {
		t.Errorf("digest mismatch: %s", digest)
	}
	if n != int64(len(content)) || !bytes.Equal(buf.Bytes(), content) {
		t.Errorf("content mismatch: n=%d", n)
	}
}

func TestValidateFetchURLRejectsNonPublic(t *testing.T) {
	c := NewClient("https://api.locktivity.com", "token", "test", false)
	for _, raw := range []string{
		"http://files.example/x",                    // non-https
		"https://user:pass@files.example/x",         // embedded credentials
		"https://127.0.0.1/x",                       // loopback
		"https://10.0.0.1/x",                        // RFC1918
		"https://169.254.169.254/latest/meta-data/", // cloud metadata
		"https://[::1]/x",                           // IPv6 loopback
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parsing %q: %v", raw, err)
		}
		if err := c.validateFetchURL(u); err == nil {
			t.Errorf("expected %q to be rejected", raw)
		}
	}
}

func TestValidateFetchIPsRejectsAnyNonPublicAddress(t *testing.T) {
	err := validateFetchIPs([]net.IP{
		net.ParseIP("93.184.216.34"),
		net.ParseIP("10.0.0.1"),
	})
	if err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("expected mixed public/private DNS results to be rejected, got %v", err)
	}
}

func TestValidateFetchURLInsecureBypass(t *testing.T) {
	c := NewClient("http://api.lvh.me:3000", "token", "test", true)
	u, _ := url.Parse("http://127.0.0.1:3000/rails/active_storage/x")
	if err := c.validateFetchURL(u); err != nil {
		t.Errorf("insecure client should allow a local URL: %v", err)
	}
}

func TestDownloadBoundsSize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 100))
	}))
	defer server.Close()

	c := NewClient(server.URL, "token", "test", true)
	c.maxDownload = 10

	var buf bytes.Buffer
	if _, _, err := c.Download(context.Background(), server.URL, &buf); err == nil || !strings.Contains(err.Error(), "maximum size") {
		t.Fatalf("expected a size-limit error, got %v", err)
	}
}

func TestReadErrorMessageRedactsSensitiveValues(t *testing.T) {
	message := readErrorMessage(strings.NewReader(`{
		"error": "Bearer secret-token https://files.example/x?signature=PDF_SIGNED_URL_CANARY&safe=1",
		"access_token": "json-token"
	}`))
	for _, forbidden := range []string{"secret-token", "PDF_SIGNED_URL_CANARY", "json-token"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("error message leaked %q: %s", forbidden, message)
		}
	}
	if !strings.Contains(message, "[REDACTED]") {
		t.Fatalf("expected redaction marker, got %s", message)
	}
}
