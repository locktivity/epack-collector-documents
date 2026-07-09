package locktivity

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExchangeClientCredentials(t *testing.T) {
	var gotForm map[string]string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/oauth2/token" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		gotForm = map[string]string{
			"grant_type":    r.PostForm.Get("grant_type"),
			"client_id":     r.PostForm.Get("client_id"),
			"client_secret": r.PostForm.Get("client_secret"),
			"scope":         r.PostForm.Get("scope"),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "minted-token", "token_type": "Bearer"})
	}))
	defer server.Close()
	useTestTransport(t, server)

	token, err := ExchangeClientCredentials(context.Background(), "", "client-1", "secret-1")
	if err != nil {
		t.Fatalf("ExchangeClientCredentials failed: %v", err)
	}
	if token != "minted-token" {
		t.Errorf("token = %q, want minted-token", token)
	}
	want := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     "client-1",
		"client_secret": "secret-1",
		"scope":         "write:document_snapshots",
	}
	for key, value := range want {
		if gotForm[key] != value {
			t.Errorf("form[%s] = %q, want %q", key, gotForm[key], value)
		}
	}
}

func TestExchangeClientCredentialsRefusesPlaintextRemote(t *testing.T) {
	// TEST-NET is parsed as non-loopback before any request is made.
	_, err := ExchangeClientCredentials(context.Background(), "http://192.0.2.10:9", "id", "secret")
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected plaintext remote refusal, got %v", err)
	}
}

func TestExchangeClientCredentialsRefusesRedirects(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/token", http.StatusFound)
	}))
	defer server.Close()
	useTestTransport(t, server)

	_, err := ExchangeClientCredentials(context.Background(), "", "id", "secret")
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected redirect refusal, got %v", err)
	}
}

func TestExchangeClientCredentialsRejectedGrant(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	useTestTransport(t, server)

	_, err := ExchangeClientCredentials(context.Background(), "", "client-1", "wrong")
	if err == nil {
		t.Fatal("expected error for rejected grant")
	}
}

func useTestTransport(t *testing.T, server *httptest.Server) {
	t.Helper()
	old := http.DefaultTransport
	http.DefaultTransport = &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, server.Listener.Addr().String())
		},
		// Route production URL requests to the test server.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	t.Cleanup(func() { http.DefaultTransport = old })
}
