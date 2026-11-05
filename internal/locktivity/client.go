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

	"github.com/locktivity/epack-collector-documents/internal/limits"
	"github.com/locktivity/epack-collector-documents/internal/redact"
	"github.com/locktivity/epack/componentsdk"
)

// DefaultBaseURL is the production API endpoint.
const DefaultBaseURL = "https://api.locktivity.com"

const snapshotsPath = "/management/v1/evidence_packs/document_snapshots"

// OpCreateSnapshot names the snapshot request in the collector result.
const OpCreateSnapshot = "locktivity.document_snapshots.create"

// The downloads, named by which of a document's files each one fetches. They
// go to the storage behind the snapshot's pre-signed URLs.
var (
	FileDownload   = componentsdk.Operation{Name: "storage.document_files.get"}
	SourceDownload = componentsdk.Operation{Name: "storage.document_sources.get"}
	TextDownload   = componentsdk.Operation{Name: "storage.document_texts.get"}
)

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

// APIError is an error response from the Locktivity API.
type APIError struct {
	StatusCode int
	Header     http.Header
	// Code is the API's machine-readable error code, such as
	// VALIDATION_ERROR.
	Code    string
	Message string
}

func newAPIError(resp *http.Response) *APIError {
	message, code := readError(resp.Body)
	return &APIError{StatusCode: resp.StatusCode, Header: resp.Header, Code: code, Message: message}
}

func (e *APIError) Error() string {
	return fmt.Sprintf("locktivity returned %d: %s", e.StatusCode, e.Message)
}

func (e *APIError) HTTPStatus() int         { return e.StatusCode }
func (e *APIError) HTTPHeader() http.Header { return e.Header }
func (e *APIError) VendorCode() string      { return e.Code }

// CollectionCode reads a 422, which the API sends when the pipeline cannot
// take a snapshot, such as one without the Documents collector. It also
// reads a 404, which the API sends when the account has no Documents feature
// or the pipeline is not in the account. Other errors go by their status.
func (e *APIError) CollectionCode() componentsdk.Code {
	switch e.StatusCode {
	case http.StatusUnprocessableEntity, http.StatusNotFound:
		return componentsdk.CodeConfigInvalid
	}
	return ""
}

// DownloadError is a download that did not answer 200.
type DownloadError struct {
	StatusCode int
	Header     http.Header
}

func (e *DownloadError) Error() string {
	return fmt.Sprintf("file download returned %d", e.StatusCode)
}

func (e *DownloadError) HTTPStatus() int         { return e.StatusCode }
func (e *DownloadError) HTTPHeader() http.Header { return e.Header }

// Client talks to the Locktivity management API and downloads the files a
// snapshot lists.
type Client struct {
	apiClient      *http.Client
	downloadClient *http.Client
	baseURL        string
	token          string
	maxDownload    int64
	maxSnapshot    int64
}

// NewClient returns a client for the API at baseURL, or DefaultBaseURL when
// baseURL is empty, that sends token with each API call. Downloads carry no
// credentials and go out through downloadTransport.
func NewClient(ctx componentsdk.CollectorContext, baseURL, token string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")
	c := &Client{
		baseURL:     baseURL,
		token:       token,
		maxDownload: limits.DownloadBytes,
		maxSnapshot: limits.SnapshotResponseBytes,
	}
	c.apiClient = componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{
		CredentialHosts: []string{hostOf(baseURL)},
	})
	c.downloadClient = componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{
		Base: downloadTransport(),
	})
	c.downloadClient.CheckRedirect = checkDownloadRedirect
	return c
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// downloadTransport resolves each download host itself and dials only public
// addresses, so neither a pre-signed URL nor a redirect can reach the
// runner's network or a cloud metadata service. Unlike the default
// transport it takes no proxy, since a proxy would dial on its behalf.
func downloadTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
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

// checkDownloadRedirect applies the download URL checks to every hop.
func checkDownloadRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= limits.DownloadRedirects {
		return refused(fmt.Sprintf("stopped after %d redirects", limits.DownloadRedirects))
	}
	return validateFetchURL(req.URL)
}

// validateFetchURL rejects download URLs that are not HTTPS or that embed
// credentials. downloadTransport checks the addresses each host resolves to.
func validateFetchURL(u *url.URL) error {
	if u.Scheme != "https" {
		return refused("refusing non-https download URL")
	}
	if u.User != nil {
		return refused("refusing download URL with embedded credentials")
	}
	return nil
}

func validateFetchIPs(ips []net.IP) error {
	if len(ips) == 0 {
		return refused("download host resolved to no addresses")
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return refused(fmt.Sprintf("refusing download URL resolving to non-public address %s", ip))
		}
	}
	return nil
}

// refused is a download the snapshot asked for that the collector will not
// make.
func refused(message string) error {
	return componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New(message))
}

// CreateSnapshot captures the document snapshot for the run, or returns the
// one already captured for runKey.
func (c *Client) CreateSnapshot(ctx context.Context, pipelineID, runKey string) (*Snapshot, error) {
	fields := map[string]string{"run_key": runKey}
	if pipelineID != "" {
		fields["pipeline_id"] = pipelineID
	}
	body, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("encoding snapshot request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, limits.APIRequestTimeout)
	defer cancel()
	// The run key makes the request idempotent: a retry gets back the
	// snapshot the first attempt captured.
	ctx = componentsdk.WithOperation(ctx, componentsdk.Operation{Name: OpCreateSnapshot, Safe: true})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+snapshotsPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.apiClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting snapshot: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, newAPIError(resp)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, c.maxSnapshot+1))
	if err != nil {
		return nil, fmt.Errorf("decoding snapshot response: %w", err)
	}
	if int64(len(raw)) > c.maxSnapshot {
		return nil, componentsdk.CodeError(componentsdk.CodeTooLarge,
			fmt.Errorf("snapshot response exceeds maximum size (%d bytes)", c.maxSnapshot))
	}
	var decoded struct {
		Snapshot
		// Documents shadows Snapshot.Documents, so a response without the
		// list can be told from one whose list is empty.
		Documents *[]Document `json:"documents"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("decoding snapshot response: %w", err)
	}
	if decoded.Documents == nil {
		return nil, componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("snapshot response has no documents list"))
	}
	snapshot := decoded.Snapshot
	snapshot.Documents = *decoded.Documents
	return &snapshot, nil
}

// Download streams the file at rawURL, a pre-signed URL from the snapshot,
// into dst and returns its SHA-256 digest and size. op names the call.
// Errors never carry the URL, whose query grants access to the file.
func (c *Client) Download(ctx context.Context, op componentsdk.Operation, rawURL string, dst io.Writer) (string, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, limits.DownloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(componentsdk.WithOperation(ctx, op), http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, refused("snapshot manifest has an unusable download URL")
	}
	if err := validateFetchURL(req.URL); err != nil {
		return "", 0, err
	}

	resp, err := c.downloadClient.Do(req)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return "", 0, fmt.Errorf("downloading file: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", 0, &DownloadError{StatusCode: resp.StatusCode, Header: resp.Header}
	}

	hasher := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, hasher), io.LimitReader(resp.Body, c.maxDownload+1))
	if err != nil {
		return "", 0, fmt.Errorf("reading file body: %w", err)
	}
	if n > c.maxDownload {
		return "", 0, componentsdk.CodeError(componentsdk.CodeTooLarge,
			fmt.Errorf("download exceeds maximum size (%d bytes)", c.maxDownload))
	}
	return hex.EncodeToString(hasher.Sum(nil)), n, nil
}

// readError returns the redacted message and the error code of an API error
// body.
func readError(body io.Reader) (string, string) {
	data, err := io.ReadAll(io.LimitReader(body, limits.ErrorResponseBytes))
	if err != nil || len(data) == 0 {
		return "no error details", ""
	}
	var payload struct {
		Code   string   `json:"code"`
		Error  string   `json:"error"`
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(data, &payload) == nil {
		switch {
		case payload.Error != "":
			return redact.String(payload.Error), payload.Code
		case len(payload.Errors) > 0:
			return redact.String(payload.Errors[0]), payload.Code
		}
	}
	return redact.String(string(data)), payload.Code
}
