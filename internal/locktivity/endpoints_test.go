package locktivity

import "testing"

func TestValidateCustomEndpointPolicy(t *testing.T) {
	if err := ValidateCustomEndpoint("endpoint", "https://locktivity.dev.example.com"); err != nil {
		t.Fatalf("should allow HTTPS custom endpoint: %v", err)
	}
	policy, err := ResolveEndpointPolicy("endpoint", "https://locktivity.dev.example.com/")
	if err != nil {
		t.Fatalf("should resolve HTTPS custom endpoint policy: %v", err)
	}
	if policy.BaseURL != "https://locktivity.dev.example.com" {
		t.Fatalf("unexpected normalized base URL: %s", policy.BaseURL)
	}

	for _, raw := range []string{
		"http://127.0.0.1:3000",
		"http://localhost:3000",
		"http://192.0.2.10:3000",
	} {
		if err := ValidateCustomEndpoint("endpoint", raw); err == nil {
			t.Fatalf("should reject plain HTTP endpoint %q", raw)
		}
	}

	for _, raw := range []string{
		"https://user:pass@locktivity.dev.example.com",
		"https://locktivity.dev.example.com?token=value",
		"https://locktivity.dev.example.com#fragment",
	} {
		if err := ValidateCustomEndpoint("endpoint", raw); err == nil {
			t.Fatalf("should reject malformed custom endpoint %q", raw)
		}
	}
}
