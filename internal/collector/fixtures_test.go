package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/locktivity/epack-collector-documents/internal/locktivity"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

const (
	kitAPIBase      = "https://api.locktivity.com"
	kitAuthBase     = "https://app.locktivity.com"
	kitFilesBase    = "https://files.locktivity.test"
	kitSnapshotURL  = kitAPIBase + "/management/v1/evidence_packs/document_snapshots"
	kitTokenURL     = kitAuthBase + "/oauth2/token"
	kitToken        = "kit-documents-token-0123456789"
	kitClientID     = "kit-client-id-0123456789"
	kitClientSecret = "kit-client-secret-0123456789"
	kitRunKey       = "kit-run-1"
	kitPipelineID   = "pl_kit"
)

// kitDocument is one document in the kit's library, with the bytes each of
// its files downloads as. A document with no file body has no file yet.
type kitDocument struct {
	id, name, source string
	version          int
	documentType     string
	warnings         []string

	artifactPath, artifactContentType string
	file                              string

	sourcePath, sourceContentType string
	sourceFile                    string

	text string

	metadata, provenance map[string]any
}

// kitLibrary is a library with each kind of document: an uploaded SOC 2
// report with text and typed details, a GitHub policy rendered to PDF with
// its Markdown source, an uploaded spreadsheet, a document with no file yet,
// and a Google Drive policy rendered to PDF without extracted text.
func kitLibrary() []kitDocument {
	return []kitDocument{
		{
			id: "doc_1", name: "Acme SOC 2 Type II 2025", source: "upload", version: 3,
			documentType: "evidencepack/soc2-report@v1", warnings: []string{},
			artifactPath: "documents/acme-soc2-2025.pdf", artifactContentType: "application/pdf",
			file: "%PDF-1.7 Acme SOC 2 Type II report for 2025",
			text: `{"document_id":"doc_1","chunks":[{"chunk_id":0,"page":1,"text":"Report of Prescient Assurance"},{"chunk_id":1,"page":2,"text":"Opinion"}]}`,
			metadata: map[string]any{
				"auditor": "Prescient Assurance", "report_type": "type_ii",
				"period_start": "2025-01-01", "period_end": "2025-12-31",
			},
			provenance: map[string]any{
				"auditor": map[string]any{"chunk_id": 0, "page": 1, "quote": "Report of Prescient Assurance"},
			},
		},
		{
			id: "doc_2", name: "Access control policy", source: "github", version: 7,
			documentType: "evidencepack/document@v1", warnings: []string{},
			artifactPath: "documents/access-control-policy.pdf", artifactContentType: "application/pdf",
			file:       "%PDF-1.7 Access control policy, rendered",
			sourcePath: "documents/access-control-policy.md", sourceContentType: "text/markdown",
			sourceFile: "# Access control policy\n\nAccess is granted by role.\n",
			text:       `{"document_id":"doc_2","chunks":[{"chunk_id":0,"page":1,"text":"Access is granted by role."}]}`,
		},
		{
			id: "doc_3", name: "Vendor inventory", source: "upload", version: 1,
			warnings:     []string{"Text was extracted from the first sheet only"},
			artifactPath: "documents/vendor-inventory.xlsx", artifactContentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
			file: "PK spreadsheet bytes for the vendor inventory",
			text: `{"document_id":"doc_3","chunks":[{"chunk_id":0,"sheet":"Vendors","row":2,"text":"Payroll processor"}]}`,
		},
		{
			id: "doc_4", name: "Incident response plan", source: "upload",
			warnings: []string{"No file available; document skipped"},
		},
		{
			id: "doc_5", name: "Data retention policy", source: "google_drive", version: 2,
			documentType: "evidencepack/document@v1", warnings: []string{},
			artifactPath: "documents/data-retention-policy.pdf", artifactContentType: "application/pdf",
			file:       "%PDF-1.7 Data retention policy, rendered",
			sourcePath: "documents/data-retention-policy.docx", sourceContentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
			sourceFile: "PK document bytes for the data retention policy",
		},
	}
}

func (d kitDocument) downloadURL(kind string) string {
	return fmt.Sprintf("%s/blobs/%s/%s?X-Amz-Expires=3600&X-Amz-Signature=sig-%s-%s", kitFilesBase, d.id, kind, d.id, kind)
}

// manifestEntry is the document as the snapshot lists it: the native file's
// checksum, size, and type, then the shipped file's, then pre-signed URLs
// for each file it has.
func (d kitDocument) manifestEntry() map[string]any {
	entry := map[string]any{
		"document_id": d.id, "name": d.name, "source": d.source, "warnings": d.warnings,
		"file_url": nil, "source_url": nil, "text_url": nil,
	}
	if d.file == "" {
		return entry
	}
	native, nativeType := d.file, d.artifactContentType
	if d.sourceFile != "" {
		native, nativeType = d.sourceFile, d.sourceContentType
	}
	entry["version_id"] = "ver_" + d.id
	entry["version_number"] = d.version
	entry["checksum"] = kitDigest(native)
	entry["byte_size"] = len(native)
	entry["content_type"] = nativeType
	entry["artifact_path"] = d.artifactPath
	entry["artifact_checksum"] = kitDigest(d.file)
	entry["artifact_content_type"] = d.artifactContentType
	entry["artifact_byte_size"] = len(d.file)
	entry["file_url"] = d.downloadURL("file")
	if d.sourceFile != "" {
		entry["source_path"] = d.sourcePath
		entry["source_url"] = d.downloadURL("source")
	}
	if d.text != "" {
		entry["text_path"] = "documents/" + d.id + "/text.json"
		entry["text_checksum"] = kitDigest(d.text)
		entry["text_url"] = d.downloadURL("text")
	}
	if d.documentType != "" {
		entry["document_type"] = d.documentType
	}
	if d.metadata != nil {
		entry["metadata"] = d.metadata
		entry["provenance"] = d.provenance
	}
	return entry
}

// kitResponses answers the snapshot request for library and each download
// it lists, in the order the collector makes them.
func kitResponses(library []kitDocument) []collectortest.Response {
	entries := make([]map[string]any, 0, len(library))
	for _, d := range library {
		entries = append(entries, d.manifestEntry())
	}
	snapshot := map[string]any{
		"id": "snap_kit", "pipeline_id": kitPipelineID, "run_key": kitRunKey, "status": "captured",
		"digest": kitDigest(kitJSON(entries)), "captured_at": "2026-01-01T00:00:00Z", "documents": entries,
	}
	responses := []collectortest.Response{{Method: http.MethodPost, URL: kitSnapshotURL, Status: http.StatusCreated, Body: kitJSON(snapshot)}}
	for _, d := range library {
		if d.file == "" {
			continue
		}
		responses = append(responses, kitDownload(d.downloadURL("file"), d.file))
		if d.sourceFile != "" {
			responses = append(responses, kitDownload(d.downloadURL("source"), d.sourceFile))
		}
		if d.text != "" {
			responses = append(responses, kitDownload(d.downloadURL("text"), d.text))
		}
	}
	return responses
}

func kitDownload(url, body string) collectortest.Response {
	return collectortest.Response{URL: url, Body: body, Header: http.Header{"Content-Type": []string{"application/octet-stream"}}}
}

// kitTokenResponse answers the client-credentials exchange.
func kitTokenResponse() collectortest.Response {
	return collectortest.Response{Method: http.MethodPost, URL: kitTokenURL, Body: kitJSON(map[string]any{
		"access_token": "kit-minted-access-token-0123456789", "token_type": "Bearer",
		"expires_in": 7200, "scope": "write:document_snapshots",
	})}
}

// kitTampered is the clean library with the access control policy's
// rendered PDF served with bytes other than the ones its checksum covers.
func kitTampered() []collectortest.Response {
	responses := kitResponses(kitLibrary())
	tampered := kitLibrary()[1].downloadURL("file")
	for i := range responses {
		if responses[i].URL == tampered {
			responses[i].Body = "%PDF-1.7 Access control policy, altered after capture"
		}
	}
	return responses
}

var kitOperations = []string{
	locktivity.OpCreateToken,
	locktivity.OpCreateSnapshot,
	locktivity.FileDownload.Name,
	locktivity.SourceDownload.Name,
	locktivity.TextDownload.Name,
}

func kitDigest(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

func kitJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("kit fixture: %v", err))
	}
	return string(raw)
}
