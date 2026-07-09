// Package locktivity implements the Locktivity snapshot API client.
package locktivity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-documents/internal/limits"
	"github.com/locktivity/epack-collector-documents/internal/redact"
)

// DefaultBaseURL is the production API endpoint.
const DefaultBaseURL = "https://api.locktivity.com"

// ErrUnauthorized indicates the access token was rejected.
var ErrUnauthorized = errors.New("locktivity rejected the access token")

// ConfigError indicates a server-side configuration rejection.
type ConfigError struct{ Message string }

func (e ConfigError) Error() string { return e.Message }

// Snapshot is a captured document snapshot manifest.
type Snapshot struct {
	ID         string     `json:"id"`
	PipelineID string     `json:"pipeline_id"`
	RunKey     string     `json:"run_key"`
	Status     string     `json:"status"`
	Digest     string     `json:"digest"`
	CapturedAt string     `json:"captured_at"`
	Documents  []Document `json:"documents"`
}

// Document is one entry in the snapshot manifest.
// Checksum, ByteSize, and ContentType describe the native file; Artifact*
// fields describe the shipped file.
type Document struct {
	DocumentID          string   `json:"document_id"`
	Name                string   `json:"name"`
	Source              string   `json:"source"`
	Warnings            []string `json:"warnings"`
	VersionID           string   `json:"version_id"`
	VersionNumber       int      `json:"version_number"`
	SourceRevision      string   `json:"source_revision"`
	EditorEmail         string   `json:"editor_email"`
	Checksum            string   `json:"checksum"`
	ByteSize            int64    `json:"byte_size"`
	ContentType         string   `json:"content_type"`
	ArtifactPath        string   `json:"artifact_path"`
	ArtifactChecksum    string   `json:"artifact_checksum"`
	ArtifactContentType string   `json:"artifact_content_type"`
	FileURL             string   `json:"file_url"`

	DocumentType     string         `json:"document_type"`
	ArtifactByteSize int64          `json:"artifact_byte_size"`
	SourcePath       string         `json:"source_path"`
	SourceURL        string         `json:"source_url"`
	TextPath         string         `json:"text_path"`
	TextChecksum     string         `json:"text_checksum"`
	TextURL          string         `json:"text_url"`
	Metadata         map[string]any `json:"metadata"`
	Provenance       map[string]any `json:"provenance"`
}

// Client talks to the Locktivity management API.
type Client struct {
	apiClient              *http.Client
	downloadClient         *http.Client
	baseURL                string
	token                  string
	userAgent              string
	allowInsecureDownloads bool
	maxDownload            int64
}

func NewClient(baseURL, token, version string, allowInsecureDownloads bool) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")
	c := &Client{
		baseURL:                baseURL,
		token:                  token,
		userAgent:              "epack-collector-documents/" + version,
		allowInsecureDownloads: allowInsecureDownloads,
		maxDownload:            limits.DownloadBytes,
	}
	// Per-call deadlines keep large downloads from consuming the API timeout.
	c.apiClient = &http.Client{}
	c.downloadClient = &http.Client{
		CheckRedirect: c.checkRedirect,
		Transport:     c.downloadTransport(),
	}
	return c
}

func (c *Client) downloadTransport() http.RoundTripper {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if c.allowInsecureDownloads {
		return transport
	}
	dialer := &net.Dialer{}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolving download host: %w", err)
		}
		if err := validateFetchIPs(ips); err != nil {
			return nil, err
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
	return transport
}

// checkRedirect re-applies the download URL guard to every hop.
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= limits.DownloadRedirects {
		return fmt.Errorf("stopped after %d redirects", limits.DownloadRedirects)
	}
	return c.validateFetchURL(req.URL)
}

// validateFetchURL rejects non-HTTPS, credentialed, or non-public targets.
func (c *Client) validateFetchURL(u *url.URL) error {
	if c.allowInsecureDownloads {
		return nil
	}
	if u.Scheme != "https" {
		return fmt.Errorf("refusing non-https download URL")
	}
	if u.User != nil {
		return fmt.Errorf("refusing download URL with embedded credentials")
	}
	ips, err := net.LookupIP(u.Hostname())
	if err != nil {
		return fmt.Errorf("resolving download host: %w", err)
	}
	return validateFetchIPs(ips)
}

func validateFetchIPs(ips []net.IP) error {
	if len(ips) == 0 {
		return fmt.Errorf("download host resolved to no addresses")
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("refusing download URL resolving to non-public address %s", ip)
		}
	}
	return nil
}

func (c *Client) CreateSnapshot(ctx context.Context, pipelineID, runKey string) (*Snapshot, error) {
	fields := map[string]string{"run_key": runKey}
	if pipelineID != "" {
		fields["pipeline_id"] = pipelineID
	}
	body, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("encoding snapshot request: %w", err)
	}

	var lastErr error
	for attempt := 1; attempt <= limits.SnapshotCreateAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(limits.SnapshotRetryDelay(attempt)):
			}
		}

		snapshot, retryable, err := c.createSnapshotOnce(ctx, body)
		if err == nil {
			return snapshot, nil
		}
		if !retryable {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func (c *Client) createSnapshotOnce(ctx context.Context, body []byte) (*Snapshot, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, limits.APIRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/management/v1/evidence_packs/document_snapshots", bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.apiClient.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("requesting snapshot: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated:
		var snapshot Snapshot
		if err := json.NewDecoder(io.LimitReader(resp.Body, limits.SnapshotResponseBytes)).Decode(&snapshot); err != nil {
			return nil, false, fmt.Errorf("decoding snapshot response: %w", err)
		}
		return &snapshot, false, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, false, ErrUnauthorized
	case resp.StatusCode == http.StatusUnprocessableEntity:
		return nil, false, ConfigError{Message: readErrorMessage(resp.Body)}
	case resp.StatusCode >= 500:
		return nil, true, fmt.Errorf("locktivity returned %d", resp.StatusCode)
	default:
		return nil, false, fmt.Errorf("locktivity returned %d: %s", resp.StatusCode, readErrorMessage(resp.Body))
	}
}

// Download streams a guarded snapshot file and returns its digest and size.
func (c *Client) Download(ctx context.Context, rawURL string, dst io.Writer) (string, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, limits.DownloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, err
	}
	if err := c.validateFetchURL(req.URL); err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.downloadClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("downloading file: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("file download returned %d", resp.StatusCode)
	}

	hasher := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, hasher), io.LimitReader(resp.Body, c.maxDownload+1))
	if err != nil {
		return "", 0, fmt.Errorf("reading file body: %w", err)
	}
	if n > c.maxDownload {
		return "", 0, fmt.Errorf("download exceeds maximum size (%d bytes)", c.maxDownload)
	}
	return hex.EncodeToString(hasher.Sum(nil)), n, nil
}

func readErrorMessage(body io.Reader) string {
	data, err := io.ReadAll(io.LimitReader(body, limits.ErrorResponseBytes))
	if err != nil || len(data) == 0 {
		return "no error details"
	}
	var payload struct {
		Error  string   `json:"error"`
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(data, &payload) == nil {
		if payload.Error != "" {
			return redact.String(payload.Error)
		}
		if len(payload.Errors) > 0 {
			return redact.String(payload.Errors[0])
		}
	}
	return redact.String(string(data))
}
