package locktivity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/locktivity/epack-collector-documents/internal/limits"
)

// DefaultAuthBaseURL is the production Locktivity auth endpoint.
const DefaultAuthBaseURL = "https://app.locktivity.com"

const (
	oauthTokenPath = "/oauth2/token"
	snapshotScope  = "write:document_snapshots"
)

// ExchangeClientCredentials mints a snapshot-scoped access token.
func ExchangeClientCredentials(ctx context.Context, authBase, clientID, clientSecret string) (string, error) {
	if authBase == "" {
		authBase = DefaultAuthBaseURL
	} else {
		var err error
		authBase, err = validateCustomEndpoint("auth endpoint", authBase)
		if err != nil {
			return "", err
		}
	}

	ctx, cancel := context.WithTimeout(ctx, limits.APIRequestTimeout)
	defer cancel()

	req, err := newClientCredentialsRequest(ctx, authBase, clientID, clientSecret)
	if err != nil {
		return "", err
	}

	// Refuse redirects because the request body carries the client secret.
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("token endpoint redirected")
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting access token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}

	return decodeAccessToken(resp.Body)
}

func newClientCredentialsRequest(ctx context.Context, authBase, clientID, clientSecret string) (*http.Request, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {snapshotScope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authBase+oauthTokenPath, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

func decodeAccessToken(body io.Reader) (string, error) {
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(body, limits.TokenResponseBytes)).Decode(&payload); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}
	if payload.AccessToken == "" {
		return "", fmt.Errorf("token response carried no access token")
	}
	return payload.AccessToken, nil
}
