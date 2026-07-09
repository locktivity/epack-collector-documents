package locktivity

import (
	"fmt"
	"net/url"
	"strings"
)

// EndpointPolicy is a validated API endpoint policy.
type EndpointPolicy struct {
	BaseURL string
}

// ResolveEndpointPolicy validates a custom base URL.
func ResolveEndpointPolicy(field, raw string) (EndpointPolicy, error) {
	if strings.TrimSpace(raw) == "" {
		return EndpointPolicy{}, nil
	}
	baseURL, err := validateCustomEndpoint(field, raw)
	if err != nil {
		return EndpointPolicy{}, err
	}
	return EndpointPolicy{BaseURL: baseURL}, nil
}

// ValidateCustomEndpoint validates a custom base URL.
func ValidateCustomEndpoint(field, raw string) error {
	_, err := validateCustomEndpoint(field, raw)
	return err
}

func validateCustomEndpoint(field, raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("%s: invalid URL: %w", field, err)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("%s: missing host", field)
	}
	if u.User != nil {
		return "", fmt.Errorf("%s: userinfo is not allowed", field)
	}
	if u.RawQuery != "" {
		return "", fmt.Errorf("%s: query parameters are not allowed", field)
	}
	if u.Fragment != "" {
		return "", fmt.Errorf("%s: fragments are not allowed", field)
	}

	switch strings.ToLower(u.Scheme) {
	case "https":
		return strings.TrimRight(u.String(), "/"), nil
	case "http":
		return "", fmt.Errorf("%s: must use HTTPS (got %q)", field, u.Scheme)
	default:
		return "", fmt.Errorf("%s: must use HTTPS (got %q)", field, u.Scheme)
	}
}
