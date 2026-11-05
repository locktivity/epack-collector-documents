package locktivity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

// inRun calls fn inside an in-process collector run whose HTTP calls go to
// rt in place of the network, or through each client's own transport when
// rt is nil, and returns the run's result.
func inRun(t *testing.T, rt http.RoundTripper, fn func(ctx componentsdk.CollectorContext)) componentsdk.InProcessResult {
	t.Helper()
	return componentsdk.RunInProcess(componentsdk.CollectorSpec{Name: "documents"}, func(ctx componentsdk.CollectorContext) error {
		fn(ctx)
		return ctx.Emit([]componentsdk.CollectedArtifact{componentsdk.JSONArtifact("artifacts/test.json", map[string]any{}, componentsdk.ArtifactMeta{})})
	}, componentsdk.InProcessOptions{
		Transport: rt,
		Sleep:     func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
	})
}

// calls returns the run's calls of op from InProcessResult.Operations. Those
// counts are kept at every level, and the collector result has them only from
// the audit level.
func calls(res componentsdk.InProcessResult, op string) componentsdk.OperationCalls {
	for _, c := range res.Operations {
		if c.Name == op {
			return c
		}
	}
	return componentsdk.OperationCalls{}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func respond(req *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: req}
}

func TestCreateSnapshot(t *testing.T) {
	var gotAuth, gotURL string
	var gotBody map[string]string
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotAuth, gotURL = req.Header.Get("Authorization"), req.URL.String()
		raw, _ := io.ReadAll(req.Body)
		gotBody = nil
		_ = json.Unmarshal(raw, &gotBody)
		return respond(req, http.StatusCreated, `{"id":"snap-1","run_key":"gha-42-1","digest":"abc","documents":[{"document_id":"doc-1","name":"Policy","artifact_path":"documents/policy.pdf","file_url":"https://files.example/x"}]}`), nil
	})

	var snapshot *Snapshot
	var errs []error
	res := inRun(t, rt, func(ctx componentsdk.CollectorContext) {
		c := NewClient(ctx, "", "token-123")
		var err error
		snapshot, err = c.CreateSnapshot(ctx.Context(), "", "gha-42-1")
		errs = append(errs, err)
		if gotBody["run_key"] != "gha-42-1" || len(gotBody) != 1 {
			t.Errorf("unexpected request body: %v", gotBody)
		}
		_, err = c.CreateSnapshot(ctx.Context(), "pl_9f8e7d", "run-2")
		errs = append(errs, err)
	})
	if err := errors.Join(errs...); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}
	if gotAuth != "Bearer token-123" || gotURL != DefaultBaseURL+snapshotsPath {
		t.Errorf("request went to %s with auth %q", gotURL, gotAuth)
	}
	if gotBody["pipeline_id"] != "pl_9f8e7d" || gotBody["run_key"] != "run-2" {
		t.Errorf("unexpected request body with pipeline: %v", gotBody)
	}
	if snapshot.ID != "snap-1" || len(snapshot.Documents) != 1 || snapshot.Documents[0].FileURL == "" {
		t.Errorf("unexpected snapshot: %+v", snapshot)
	}
	if c := calls(res, OpCreateSnapshot); c.Calls != 2 {
		t.Errorf("ledger = %+v, want two named calls", c)
	}
}

func TestCreateSnapshotClassifiesErrors(t *testing.T) {
	cases := []struct {
		name, body  string
		status      int
		code        componentsdk.Code
		vendorCode  string
		wantMessage string
	}{
		{"rejected token", `{"errors":["Unauthorized"],"code":"UNAUTHORIZED"}`, http.StatusUnauthorized, componentsdk.CodeAuthFailed, "UNAUTHORIZED", "Unauthorized"},
		{"missing scope", `{"errors":["Insufficient scope"],"code":"INSUFFICIENT_SCOPE"}`, http.StatusForbidden, componentsdk.CodePermissionDenied, "INSUFFICIENT_SCOPE", "Insufficient scope"},
		{"pipeline without the collector", `{"errors":["Pipeline has no documents collector"],"code":"VALIDATION_ERROR"}`, http.StatusUnprocessableEntity, componentsdk.CodeConfigInvalid, "VALIDATION_ERROR", "Pipeline has no documents collector"},
		{"account without the Documents feature", `{"errors":["Not found"],"code":"NOT_FOUND"}`, http.StatusNotFound, componentsdk.CodeConfigInvalid, "NOT_FOUND", "Not found"},
		{"pipeline outside the account", `{"errors":["Couldn't find EvidencePacks::Pipeline"],"code":"NOT_FOUND"}`, http.StatusNotFound, componentsdk.CodeConfigInvalid, "NOT_FOUND", "Couldn't find EvidencePacks::Pipeline"},
		{"server error", `oops`, http.StatusBadGateway, componentsdk.CodeVendorError, "", "oops"},
		{"no documents list", `{"id":"snap-1"}`, http.StatusCreated, componentsdk.CodeInvalidResponse, "", "no documents list"},
		{"truncated body", `{"id":"snap-1","docu`, http.StatusCreated, componentsdk.CodeInvalidResponse, "", "decoding snapshot response"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return respond(req, tc.status, tc.body), nil
			})
			var err error
			inRun(t, rt, func(ctx componentsdk.CollectorContext) {
				_, err = NewClient(ctx, "", "token").CreateSnapshot(ctx.Context(), "", "run-1")
			})
			if got := componentsdk.Classify(err); got != tc.code {
				t.Errorf("code = %s, want %s (err %v)", got, tc.code, err)
			}
			if got := componentsdk.VendorCodeOf(err); got != tc.vendorCode {
				t.Errorf("vendor code = %q, want %q", got, tc.vendorCode)
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantMessage) {
				t.Errorf("error %v does not mention %q", err, tc.wantMessage)
			}
		})
	}
}

// The run key makes snapshot creation idempotent, so the SDK retries it.
func TestCreateSnapshotIsRetriedOnServerErrors(t *testing.T) {
	attempts := 0
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		attempts++
		if attempts < 3 {
			return respond(req, http.StatusBadGateway, ""), nil
		}
		return respond(req, http.StatusOK, `{"id":"snap-1","documents":[]}`), nil
	})

	var snapshot *Snapshot
	var err error
	res := inRun(t, rt, func(ctx componentsdk.CollectorContext) {
		snapshot, err = NewClient(ctx, "", "token").CreateSnapshot(ctx.Context(), "", "run-1")
	})
	if err != nil {
		t.Fatalf("CreateSnapshot failed after retries: %v", err)
	}
	if snapshot.ID != "snap-1" || snapshot.Documents == nil {
		t.Errorf("unexpected snapshot: %+v", snapshot)
	}
	if c := calls(res, OpCreateSnapshot); c.Calls != 1 || c.Attempts != 3 {
		t.Errorf("ledger = %+v, want one call that took three attempts", c)
	}
}

func TestDownload(t *testing.T) {
	content := []byte("%PDF-1.4 downloaded content")
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://93.184.216.34/document.pdf" {
			t.Errorf("unexpected download URL: %s", req.URL)
		}
		if req.Header.Get("Authorization") != "" {
			t.Error("pre-signed downloads must not carry the API token")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(content)), Header: make(http.Header), Request: req}, nil
	})

	var buf bytes.Buffer
	var digest string
	var n int64
	var err error
	res := inRun(t, rt, func(ctx componentsdk.CollectorContext) {
		digest, n, err = NewClient(ctx, "", "token").Download(ctx.Context(), TextDownload, "https://93.184.216.34/document.pdf", &buf)
	})
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
	if c := calls(res, TextDownload.Name); c.Calls != 1 {
		t.Errorf("ledger = %+v, want the download named %s", res.Operations, TextDownload.Name)
	}
}

func TestDownloadBoundsSize(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(make([]byte, 100))), Header: make(http.Header), Request: req}, nil
	})

	var err error
	inRun(t, rt, func(ctx componentsdk.CollectorContext) {
		c := NewClient(ctx, "", "token")
		c.maxDownload = 10
		_, _, err = c.Download(ctx.Context(), FileDownload, "https://93.184.216.34/document.pdf", &bytes.Buffer{})
	})
	if err == nil || !strings.Contains(err.Error(), "maximum size") || componentsdk.Classify(err) != componentsdk.CodeTooLarge {
		t.Fatalf("expected a too_large size-limit error, got %v", err)
	}
}

// A snapshot answer over the collector's limit is too_large.
func TestCreateSnapshotBoundsSize(t *testing.T) {
	body := `{"id":"snap-1","documents":[]}`
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return respond(req, http.StatusCreated, body), nil
	})
	for limit, want := range map[int64]componentsdk.Code{int64(len(body)): "", int64(len(body) - 1): componentsdk.CodeTooLarge} {
		var err error
		inRun(t, rt, func(ctx componentsdk.CollectorContext) {
			c := NewClient(ctx, "", "token")
			c.maxSnapshot = limit
			_, err = c.CreateSnapshot(ctx.Context(), "", "run-1")
		})
		if want == "" && err != nil {
			t.Errorf("limit %d: a snapshot at the limit failed: %v", limit, err)
		}
		if want != "" && componentsdk.Classify(err) != want {
			t.Errorf("limit %d: err %v, want %s", limit, err, want)
		}
	}
}

func TestDownloadErrorsLeaveOutTheSignedURL(t *testing.T) {
	const signed = "https://files.example/document.pdf?X-Amz-Signature=SIGNATURE_CANARY"
	cases := map[string]roundTripFunc{
		"connection reset": func(*http.Request) (*http.Response, error) {
			return nil, &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
		},
		"redirect to plain HTTP": func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"http://files.example/x?X-Amz-Signature=SIGNATURE_CANARY"}}, Body: http.NoBody, Request: req}, nil
		},
		"status": func(req *http.Request) (*http.Response, error) {
			return respond(req, http.StatusForbidden, `<Error><Code>AccessDenied</Code></Error>`), nil
		},
	}
	want := map[string]componentsdk.Code{
		"connection reset":       componentsdk.CodeVendorError,
		"redirect to plain HTTP": componentsdk.CodeInvalidResponse,
		"status":                 componentsdk.CodePermissionDenied,
	}
	for name, rt := range cases {
		t.Run(name, func(t *testing.T) {
			var err error
			inRun(t, rt, func(ctx componentsdk.CollectorContext) {
				_, _, err = NewClient(ctx, "", "token").Download(ctx.Context(), FileDownload, signed, &bytes.Buffer{})
			})
			if err == nil || strings.Contains(err.Error(), "SIGNATURE_CANARY") {
				t.Fatalf("error %v carries the signed URL", err)
			}
			if got := componentsdk.Classify(err); got != want[name] {
				t.Errorf("code = %s, want %s (err %v)", got, want[name], err)
			}
		})
	}
}

// The guard tests below exercise downloadTransport directly: collectortest
// runs replace a client's base transport, so they never reach the guard.

func TestDownloadTransportRefusesNonPublicAddresses(t *testing.T) {
	for _, raw := range []string{
		"https://127.0.0.1/x",                       // loopback
		"https://10.0.0.1/x",                        // RFC1918
		"https://169.254.169.254/latest/meta-data/", // cloud metadata
		"https://[::1]/x",                           // IPv6 loopback
		"https://0.0.0.0/x",                         // unspecified
	} {
		req, err := http.NewRequest(http.MethodGet, raw, nil)
		if err != nil {
			t.Fatalf("building request for %q: %v", raw, err)
		}
		resp, err := downloadTransport().RoundTrip(req)
		if err == nil {
			_ = resp.Body.Close()
			t.Errorf("expected %q to be refused", raw)
			continue
		}
		if !strings.Contains(err.Error(), "non-public") || componentsdk.Classify(err) != componentsdk.CodeInvalidResponse {
			t.Errorf("%q: got %v, want an invalid_response refusal of a non-public address", raw, err)
		}
	}
}

func TestDownloadTransportTakesNoProxy(t *testing.T) {
	if downloadTransport().Proxy != nil {
		t.Fatal("a proxy would dial on the transport's behalf and bypass its address check")
	}
}

// Every redirect hop goes through the guard, which refuses a private target
// as it dials.
func TestDownloadRefusesARedirectToANonPublicAddress(t *testing.T) {
	guard := downloadTransport()
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "files.example" {
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://10.0.0.1/internal"}}, Body: http.NoBody, Request: req}, nil
		}
		return guard.RoundTrip(req)
	})
	var err error
	inRun(t, rt, func(ctx componentsdk.CollectorContext) {
		_, _, err = NewClient(ctx, "", "token").Download(ctx.Context(), FileDownload, "https://files.example/document.pdf", &bytes.Buffer{})
	})
	if err == nil || !strings.Contains(err.Error(), "non-public address 10.0.0.1") {
		t.Fatalf("expected the redirect to a private address to be refused, got %v", err)
	}
}

// A real run's download client sends through the guard.
func TestDownloadClientRefusesNonPublicAddresses(t *testing.T) {
	var err error
	inRun(t, nil, func(ctx componentsdk.CollectorContext) {
		_, _, err = NewClient(ctx, "", "token").Download(ctx.Context(), FileDownload, "https://169.254.169.254/latest/meta-data/", &bytes.Buffer{})
	})
	if err == nil || !strings.Contains(err.Error(), "non-public") || componentsdk.Classify(err) != componentsdk.CodeInvalidResponse {
		t.Fatalf("expected the download client to refuse a non-public address, got %v", err)
	}
}

func TestValidateFetchURLRejectsUnsafeURLs(t *testing.T) {
	for _, raw := range []string{
		"http://files.example/x",                       // non-https
		"https://user:pass@files.example/x",            // embedded credentials
		"http://127.0.0.1:3000/rails/active_storage/x", // plain HTTP loopback
		"ftp://files.example/x",                        // other scheme
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parsing %q: %v", raw, err)
		}
		if err := validateFetchURL(u); err == nil || componentsdk.Classify(err) != componentsdk.CodeInvalidResponse {
			t.Errorf("expected %q to be rejected as invalid_response, got %v", raw, err)
		}
	}
}

func TestCheckDownloadRedirectBoundsHops(t *testing.T) {
	next, _ := http.NewRequest(http.MethodGet, "https://files.example/x", nil)
	via := make([]*http.Request, 5)
	if err := checkDownloadRedirect(next, via); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Fatalf("expected the sixth hop to be refused, got %v", err)
	}
	if err := checkDownloadRedirect(next, via[:1]); err != nil {
		t.Fatalf("an HTTPS hop within the limit should pass, got %v", err)
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

func TestReadErrorRedactsSensitiveValues(t *testing.T) {
	message, code := readError(strings.NewReader(`{
		"error": "Bearer secret-token https://files.example/x?signature=PDF_SIGNED_URL_CANARY&safe=1",
		"code": "FORBIDDEN",
		"access_token": "json-token"
	}`))
	for _, forbidden := range []string{"secret-token", "PDF_SIGNED_URL_CANARY", "json-token"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("error message leaked %q: %s", forbidden, message)
		}
	}
	if !strings.Contains(message, "[REDACTED]") || code != "FORBIDDEN" {
		t.Fatalf("expected a redacted message and the code, got %q, %q", message, code)
	}
}
