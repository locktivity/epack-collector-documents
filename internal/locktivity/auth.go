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
	"github.com/locktivity/epack-collector-documents/internal/redact"
	"github.com/locktivity/epack/componentsdk"
)

// DefaultAuthBaseURL is the production Locktivity auth endpoint.
const DefaultAuthBaseURL = "https://app.locktivity.com"

// OpCreateToken names the client-credentials exchange in the collector
// result.
const OpCreateToken = "locktivity.token.create"

// The variables the collector reads its credentials from.
const (
	EnvDocumentsToken = "LOCKTIVITY_DOCUMENTS_TOKEN"
	EnvClientID       = "LOCKTIVITY_CLIENT_ID"
	EnvClientSecret   = "LOCKTIVITY_CLIENT_SECRET"
)

const (
	oauthTokenPath = "/oauth2/token"
	snapshotScope  = "write:document_snapshots"
)

// Token is an access token the exchange minted.
type Token struct {
	AccessToken string
	// Scopes lists the scopes the server granted.
	Scopes []string
}

// TokenError is an error response from the token endpoint.
type TokenError struct {
	StatusCode int
	Header     http.Header
	// OAuthCode is the RFC 6749 error code, such as invalid_client.
	OAuthCode   string
	Description string
}

func newTokenError(resp *http.Response) *TokenError {
	e := &TokenError{StatusCode: resp.StatusCode, Header: resp.Header}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limits.ErrorResponseBytes))
	if err != nil {
		return e
	}
	var payload struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if json.Unmarshal(data, &payload) == nil {
		e.OAuthCode = payload.Error
		e.Description = redact.String(payload.ErrorDescription)
	}
	return e
}

func (e *TokenError) Error() string {
	msg := fmt.Sprintf("token request returned %d", e.StatusCode)
	if e.OAuthCode != "" {
		msg += ": " + e.OAuthCode
	}
	if e.Description != "" {
		msg += " (" + e.Description + ")"
	}
	return msg
}

func (e *TokenError) HTTPStatus() int         { return e.StatusCode }
func (e *TokenError) HTTPHeader() http.Header { return e.Header }
func (e *TokenError) VendorCode() string      { return e.OAuthCode }

// CollectionCode reads the RFC 6749 error code of a 400 or 401 with
// componentsdk.OAuthErrorCode, except unauthorized_client: Locktivity sends it
// when the API application signed in but its grant flows leave out client
// credentials, so the credential works and lacks a permission. Errors under
// other statuses go by their status, so a 5xx is a vendor error rather than a
// rejected credential.
func (e *TokenError) CollectionCode() componentsdk.Code {
	if e.StatusCode != http.StatusBadRequest && e.StatusCode != http.StatusUnauthorized {
		return ""
	}
	if e.OAuthCode == "unauthorized_client" {
		return componentsdk.CodePermissionDenied
	}
	code, _ := componentsdk.OAuthErrorCode(e.OAuthCode)
	return code
}

// ExchangeClientCredentials mints a snapshot-scoped access token at authBase,
// or DefaultAuthBaseURL when authBase is empty.
func ExchangeClientCredentials(ctx componentsdk.CollectorContext, authBase, clientID, clientSecret string) (*Token, error) {
	if authBase == "" {
		authBase = DefaultAuthBaseURL
	} else {
		var err error
		authBase, err = validateCustomEndpoint("insecure_auth_endpoint", authBase)
		if err != nil {
			return nil, componentsdk.CodeError(componentsdk.CodeConfigInvalid, err)
		}
	}

	client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{
		CredentialHosts: []string{hostOf(authBase)},
	})
	// Refuse redirects because the request body carries the client secret.
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("the token request was redirected"))
	}

	reqCtx, cancel := context.WithTimeout(ctx.Context(), limits.APIRequestTimeout)
	defer cancel()
	// The exchange only mints a token, so a retry is harmless.
	reqCtx = componentsdk.WithOperation(reqCtx, componentsdk.Operation{Name: OpCreateToken, Safe: true})
	req, err := newClientCredentialsRequest(reqCtx, authBase, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting access token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, newTokenError(resp)
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

func decodeAccessToken(body io.Reader) (*Token, error) {
	var payload struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	if err := json.NewDecoder(io.LimitReader(body, limits.TokenResponseBytes)).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decoding the exchange response: %w", err)
	}
	if payload.AccessToken == "" {
		return nil, componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("the exchange response has no access token"))
	}
	return &Token{AccessToken: payload.AccessToken, Scopes: strings.Fields(payload.Scope)}, nil
}
