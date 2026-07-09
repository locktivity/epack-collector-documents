package locktivity

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// PlainHTTPLoopbackDevBuilds reports whether dev endpoint overrides are enabled.
func PlainHTTPLoopbackDevBuilds() bool {
	return allowCustomLoopbackDevEndpoints
}

// EndpointPolicy is a validated API endpoint policy.
type EndpointPolicy struct {
	BaseURL                string
	AllowInsecureDownloads bool
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
	u, err := url.Parse(baseURL)
	if err != nil {
		return EndpointPolicy{}, err
	}
	return EndpointPolicy{
		BaseURL:                baseURL,
		AllowInsecureDownloads: allowInsecureDownloadsForURL(u),
	}, nil
}

// ValidateCustomEndpoint validates a custom base URL.
func ValidateCustomEndpoint(field, raw string) error {
	_, err := validateCustomEndpoint(field, raw)
	return err
}

// AllowInsecureDownloadsForEndpoint reports whether local downloads are allowed.
func AllowInsecureDownloadsForEndpoint(raw string) bool {
	policy, err := ResolveEndpointPolicy("endpoint", raw)
	if err != nil {
		return false
	}
	return policy.AllowInsecureDownloads
}

func allowInsecureDownloadsForURL(u *url.URL) bool {
	return allowCustomLoopbackDevEndpoints &&
		strings.ToLower(u.Scheme) == "http" &&
		u.Hostname() != "" &&
		hostResolvesOnlyToLoopback(u.Hostname())
}

func validateCustomEndpoint(field, raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("%s: invalid URL: %w", field, err)
	}
	if !allowCustomLoopbackDevEndpoints {
		return "", fmt.Errorf("%s: custom endpoints are allowed only for loopback hosts in dev builds", field)
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

	if !hostResolvesOnlyToLoopback(u.Hostname()) {
		return "", fmt.Errorf("%s: custom endpoints are allowed only for loopback hosts in dev builds", field)
	}

	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return strings.TrimRight(u.String(), "/"), nil
	default:
		return "", fmt.Errorf("%s: must use HTTP or HTTPS for a dev loopback endpoint (got %q)", field, u.Scheme)
	}
}

func hostResolvesOnlyToLoopback(host string) bool {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !ip.IsLoopback() {
			return false
		}
	}
	return true
}
