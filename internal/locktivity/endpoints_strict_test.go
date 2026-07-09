//go:build !dev

package locktivity

import "testing"

func TestValidateCustomEndpointRejectsCustomEndpointsInRelease(t *testing.T) {
	if err := ValidateCustomEndpoint("endpoint", "http://127.0.0.1:3000"); err == nil {
		t.Fatal("release build should reject plain HTTP loopback endpoint")
	}
	if _, err := ResolveEndpointPolicy("endpoint", "http://127.0.0.1:3000"); err == nil {
		t.Fatal("release build should reject policy for plain HTTP loopback endpoint")
	}
	if err := ValidateCustomEndpoint("endpoint", "https://api.example.test"); err == nil {
		t.Fatal("release build should reject HTTPS custom endpoint")
	}
	if AllowInsecureDownloadsForEndpoint("http://127.0.0.1:3000") {
		t.Fatal("release build should not relax download SSRF checks for loopback HTTP")
	}
}
