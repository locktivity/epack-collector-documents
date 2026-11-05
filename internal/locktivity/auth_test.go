package locktivity

import (
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

func TestExchangeClientCredentials(t *testing.T) {
	var gotURL string
	var gotForm url.Values
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotURL = req.URL.String()
		raw, _ := io.ReadAll(req.Body)
		gotForm, _ = url.ParseQuery(string(raw))
		return respond(req, http.StatusOK, `{"access_token":"minted-token","token_type":"Bearer","scope":"write:document_snapshots"}`), nil
	})

	var token *Token
	var err error
	res := inRun(t, rt, func(ctx componentsdk.CollectorContext) {
		token, err = ExchangeClientCredentials(ctx, "", "client-1", "secret-1")
	})
	if err != nil {
		t.Fatalf("ExchangeClientCredentials failed: %v", err)
	}
	if token.AccessToken != "minted-token" || !reflect.DeepEqual(token.Scopes, []string{"write:document_snapshots"}) {
		t.Errorf("token = %+v", token)
	}
	if gotURL != DefaultAuthBaseURL+"/oauth2/token" {
		t.Errorf("exchange went to %s", gotURL)
	}
	want := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     "client-1",
		"client_secret": "secret-1",
		"scope":         "write:document_snapshots",
	}
	for key, value := range want {
		if gotForm.Get(key) != value {
			t.Errorf("form[%s] = %q, want %q", key, gotForm.Get(key), value)
		}
	}
	if c := calls(res, OpCreateToken); c.Calls != 1 {
		t.Errorf("ledger = %+v, want the exchange named %s", res.Operations, OpCreateToken)
	}
}

func TestExchangeClientCredentialsRefusesRedirects(t *testing.T) {
	followed := false
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "app.locktivity.com" {
			followed = true
		}
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://elsewhere.example/token"}}, Body: http.NoBody, Request: req}, nil
	})

	var err error
	inRun(t, rt, func(ctx componentsdk.CollectorContext) {
		_, err = ExchangeClientCredentials(ctx, "", "id", "secret")
	})
	if err == nil || !strings.Contains(err.Error(), "redirect") || componentsdk.Classify(err) != componentsdk.CodeInvalidResponse {
		t.Fatalf("expected an invalid_response redirect refusal, got %v", err)
	}
	if followed {
		t.Fatal("the client secret followed the redirect")
	}
}

// OAuth errors are classified per RFC 6749, and a token endpoint that is
// down is a vendor error, not a rejected credential.
func TestExchangeClientCredentialsClassifiesErrors(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		code       componentsdk.Code
		vendorCode string
	}{
		{"unknown client", http.StatusUnauthorized, `{"error":"invalid_client","error_description":"Client authentication failed."}`, componentsdk.CodeAuthFailed, "invalid_client"},
		{"unknown client as 400", http.StatusBadRequest, `{"error":"invalid_client"}`, componentsdk.CodeAuthFailed, "invalid_client"},
		{"revoked grant", http.StatusBadRequest, `{"error":"invalid_grant"}`, componentsdk.CodeAuthFailed, "invalid_grant"},
		{"grant type not allowed", http.StatusBadRequest, `{"error":"unauthorized_client"}`, componentsdk.CodePermissionDenied, "unauthorized_client"},
		{"scope not granted", http.StatusBadRequest, `{"error":"invalid_scope"}`, componentsdk.CodePermissionDenied, "invalid_scope"},
		{"malformed request", http.StatusBadRequest, `{"error":"invalid_request"}`, componentsdk.CodeConfigInvalid, "invalid_request"},
		{"grant type not supported", http.StatusBadRequest, `{"error":"unsupported_grant_type"}`, componentsdk.CodeConfigInvalid, "unsupported_grant_type"},
		{"unavailable as 400", http.StatusBadRequest, `{"error":"temporarily_unavailable"}`, componentsdk.CodeVendorError, "temporarily_unavailable"},
		{"unknown error as 400", http.StatusBadRequest, `{"error":"something_else"}`, componentsdk.CodeInvalidResponse, "something_else"},
		{"rejected without a body", http.StatusUnauthorized, ``, componentsdk.CodeAuthFailed, ""},
		{"endpoint unavailable", http.StatusServiceUnavailable, `<html>down</html>`, componentsdk.CodeVendorError, ""},
		{"throttled", http.StatusTooManyRequests, `{"error":"slow_down"}`, componentsdk.CodeRateLimited, "slow_down"},
		{"no access token", http.StatusOK, `{"token_type":"Bearer"}`, componentsdk.CodeInvalidResponse, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return respond(req, tc.status, tc.body), nil
			})
			var err error
			inRun(t, rt, func(ctx componentsdk.CollectorContext) {
				_, err = ExchangeClientCredentials(ctx, "", "client-1", "secret-1")
			})
			if got := componentsdk.Classify(err); got != tc.code {
				t.Errorf("code = %s, want %s (err %v)", got, tc.code, err)
			}
			if got := componentsdk.VendorCodeOf(err); got != tc.vendorCode {
				t.Errorf("vendor code = %q, want %q", got, tc.vendorCode)
			}
			if err != nil && strings.Contains(err.Error(), "secret-1") {
				t.Errorf("error carries the client secret: %v", err)
			}
		})
	}
}

func TestExchangeClientCredentialsRefusesPlaintext(t *testing.T) {
	sent := false
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		sent = true
		return respond(req, http.StatusOK, `{"access_token":"minted"}`), nil
	})
	var err error
	inRun(t, rt, func(ctx componentsdk.CollectorContext) {
		_, err = ExchangeClientCredentials(ctx, "http://192.0.2.10:9", "id", "secret")
	})
	if err == nil || !strings.Contains(err.Error(), "must use HTTPS") || componentsdk.Classify(err) != componentsdk.CodeConfigInvalid {
		t.Fatalf("expected a config_invalid plaintext refusal, got %v", err)
	}
	if sent {
		t.Fatal("the client secret went to a plaintext endpoint")
	}
}

func TestExchangeClientCredentialsUsesTheCustomEndpoint(t *testing.T) {
	var gotURL string
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotURL = req.URL.String()
		return respond(req, http.StatusOK, `{"access_token":"minted"}`), nil
	})
	inRun(t, rt, func(ctx componentsdk.CollectorContext) {
		if _, err := ExchangeClientCredentials(ctx, "https://app.example.test/", "id", "secret"); err != nil {
			t.Errorf("exchange failed: %v", err)
		}
	})
	if gotURL != "https://app.example.test/oauth2/token" {
		t.Errorf("exchange went to %s", gotURL)
	}
}
