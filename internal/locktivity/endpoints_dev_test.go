//go:build dev

package locktivity

import "testing"

func TestValidateCustomEndpointAllowsPlainHTTPLoopbackInDev(t *testing.T) {
	if err := ValidateCustomEndpoint("endpoint", "http://127.0.0.1:3000"); err != nil {
		t.Fatalf("dev build should allow plain HTTP loopback endpoint: %v", err)
	}
	policy, err := ResolveEndpointPolicy("endpoint", "http://127.0.0.1:3000/")
	if err != nil {
		t.Fatalf("dev build should resolve loopback HTTP policy: %v", err)
	}
	if policy.BaseURL != "http://127.0.0.1:3000" {
		t.Fatalf("unexpected normalized base URL: %s", policy.BaseURL)
	}
	if !policy.AllowInsecureDownloads || !AllowInsecureDownloadsForEndpoint("http://127.0.0.1:3000") {
		t.Fatal("dev build should relax download SSRF checks for loopback HTTP")
	}
}

func TestValidateCustomEndpointAllowsHTTPSLoopbackInDev(t *testing.T) {
	policy, err := ResolveEndpointPolicy("endpoint", "https://127.0.0.1:3000/")
	if err != nil {
		t.Fatalf("dev build should resolve loopback HTTPS policy: %v", err)
	}
	if policy.BaseURL != "https://127.0.0.1:3000" {
		t.Fatalf("unexpected normalized base URL: %s", policy.BaseURL)
	}
	if policy.AllowInsecureDownloads {
		t.Fatal("HTTPS loopback endpoint should not relax download SSRF checks")
	}
}

func TestValidateCustomEndpointRejectsPlainHTTPRemoteInDev(t *testing.T) {
	if err := ValidateCustomEndpoint("endpoint", "http://192.0.2.10:3000"); err == nil {
		t.Fatal("dev build should reject plain HTTP non-loopback endpoint")
	}
}

func TestValidateCustomEndpointRejectsHTTPSRemoteInDev(t *testing.T) {
	if err := ValidateCustomEndpoint("endpoint", "https://api.example.test"); err == nil {
		t.Fatal("dev build should reject HTTPS non-loopback endpoint")
	}
}
