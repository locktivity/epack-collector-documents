// Package redact contains shared redaction rules.
package redact

import (
	"regexp"
	"strings"
)

var sensitiveKeys = map[string]struct{}{
	"file_url":       {},
	"source_url":     {},
	"text_url":       {},
	"download_url":   {},
	"signed_url":     {},
	"presigned_url":  {},
	"pre_signed_url": {},
	"client_secret":  {},
	"authorization":  {},
	"bearer":         {},
	"access_token":   {},
	"refresh_token":  {},
	"id_token":       {},
	"api_key":        {},
	"apikey":         {},
	"password":       {},
	"secret":         {},
	"token":          {},
}

var stringPatterns = []struct {
	pattern     *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+`), `${1}[REDACTED]`},
	{regexp.MustCompile(`(?i)("(?:access_token|client_secret|refresh_token|id_token|token)"\s*:\s*")[^"]+`), `${1}[REDACTED]`},
	{regexp.MustCompile(`(?i)((?:access_token|client_secret|refresh_token|id_token|token|signature|sig|x-amz-signature)=)[^&\s"]+`), `${1}[REDACTED]`},
}

// String redacts token-like values.
func String(value string) string {
	for _, rule := range stringPatterns {
		value = rule.pattern.ReplaceAllString(value, rule.replacement)
	}
	return value
}

// Map returns a recursively redacted copy of src.
func Map(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	dst := map[string]any{}
	for key, value := range src {
		if SensitiveKey(key) {
			continue
		}
		if sanitized, ok := Value(value); ok {
			dst[key] = sanitized
		}
	}
	if len(dst) == 0 {
		return nil
	}
	return dst
}

// SensitiveKey reports whether a field name should be omitted.
func SensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(key, "-", "_")))
	_, sensitive := sensitiveKeys[normalized]
	return sensitive
}

// Value redacts a metadata value recursively.
func Value(value any) (any, bool) {
	switch typed := value.(type) {
	case string:
		return String(typed), true
	case map[string]any:
		cleaned := Map(typed)
		return cleaned, len(cleaned) > 0
	case []any:
		cleaned := make([]any, 0, len(typed))
		for _, item := range typed {
			if sanitized, ok := Value(item); ok {
				cleaned = append(cleaned, sanitized)
			}
		}
		return cleaned, len(cleaned) > 0
	default:
		return value, true
	}
}
