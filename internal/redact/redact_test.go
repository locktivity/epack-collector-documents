package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMapDropsSensitiveKeysAndRedactsStrings(t *testing.T) {
	got := Map(map[string]any{
		"auditor":       "Prescient Assurance",
		"access_token":  "TOKEN_CANARY",
		"callback_url":  "https://example.test/callback?signature=SIGNATURE_CANARY&safe=1",
		"authorization": "Bearer AUTH_CANARY",
		"source_url":    "SOURCE_URL_CANARY",
		"nested": map[string]any{
			"file-url": "URL_CANARY",
			"quote":    "Bearer BEARER_CANARY",
		},
		"list": []any{
			map[string]any{"client_secret": "SECRET_CANARY"},
			"sig=LIST_SIGNATURE_CANARY",
		},
	})

	if got["auditor"] != "Prescient Assurance" {
		t.Fatalf("safe metadata was not preserved: %+v", got)
	}
	if _, ok := got["access_token"]; ok {
		t.Fatalf("sensitive key was preserved: %+v", got)
	}
	if _, ok := got["authorization"]; ok {
		t.Fatalf("authorization key was preserved: %+v", got)
	}

	nested, ok := got["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested metadata was not preserved as a map: %+v", got)
	}
	if _, ok := nested["file-url"]; ok {
		t.Fatalf("nested sensitive key was preserved: %+v", nested)
	}

	rawBytes, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal redacted map: %v", err)
	}
	raw := string(rawBytes)
	for _, forbidden := range []string{
		"TOKEN_CANARY",
		"SIGNATURE_CANARY",
		"AUTH_CANARY",
		"SOURCE_URL_CANARY",
		"URL_CANARY",
		"BEARER_CANARY",
		"SECRET_CANARY",
		"LIST_SIGNATURE_CANARY",
	} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("redacted map leaked %q: %s", forbidden, raw)
		}
	}
	if !strings.Contains(raw, "[REDACTED]") {
		t.Fatalf("expected redaction marker in %s", raw)
	}
}

func TestMapOmitsEmptySensitiveOnlyChildren(t *testing.T) {
	got := Map(map[string]any{
		"nested": map[string]any{"token": "TOKEN_CANARY"},
		"source": map[string]any{"source_url": "SOURCE_URL_CANARY"},
		"list":   []any{map[string]any{"client_secret": "SECRET_CANARY"}},
	})
	if len(got) != 0 {
		t.Fatalf("expected sensitive-only metadata to be omitted, got %+v", got)
	}
}
