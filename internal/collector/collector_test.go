package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/locktivity/epack-collector-documents/internal/locktivity"
	"github.com/locktivity/epack/componentsdk"
)

type fakeClient struct {
	snapshot *locktivity.Snapshot
	files    map[string][]byte
	errs     map[string]error
	ops      []string
}

func (f *fakeClient) CreateSnapshot(ctx context.Context, pipelineID, runKey string) (*locktivity.Snapshot, error) {
	return f.snapshot, nil
}

func (f *fakeClient) Download(ctx context.Context, op componentsdk.Operation, url string, dst io.Writer) (string, int64, error) {
	f.ops = append(f.ops, op.Name)
	content := f.files[url]
	n, err := dst.Write(content)
	if downloadErr := f.errs[url]; downloadErr != nil {
		return "", int64(n), downloadErr
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), int64(n), err
}

// dirStager is a test Stager backed by a temp directory.
type dirStager struct{ dir string }

func (d dirStager) StageFile(relPath string) (*os.File, string, error) {
	p := filepath.Join(d.dir, relPath)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, "", err
	}
	f, err := os.Create(p)
	return f, filepath.ToSlash(relPath), err
}

func digestOf(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func snapshotWith(docs ...locktivity.Document) *locktivity.Snapshot {
	return &locktivity.Snapshot{
		ID:         "snap-1",
		PipelineID: "pipe-1",
		RunKey:     "gha-42-1",
		Digest:     "manifest-digest",
		CapturedAt: "2026-07-07T10:00:00Z",
		Documents:  docs,
	}
}

// collect runs Collect with a temp-dir stager and returns its output, the
// gaps it recorded, and the staging directory.
func collect(t *testing.T, client *fakeClient) (*Output, []componentsdk.Gap, string) {
	t.Helper()
	outputDir := t.TempDir()
	rec := &componentsdk.Recorder{}
	output, err := Collect(context.Background(), Config{
		RunKey:   "run-1",
		Stager:   dirStager{dir: outputDir},
		Recorder: rec,
	}, client)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	return output, rec.Gaps(), outputDir
}

// expectLeftOut checks that the document at index kept its index entry
// without the pointers to its files, and that each of those pointers has a
// gap with code and a detail mentioning want.
func expectLeftOut(t *testing.T, output *Output, gaps []componentsdk.Gap, index int, code componentsdk.Code, want string, pointers ...string) {
	t.Helper()
	raw, err := json.Marshal(output.Index.Documents[index])
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, pointer := range pointers {
		if _, ok := fields[pointer]; ok {
			t.Errorf("left-out document still has %s: %s", pointer, raw)
		}
		found := false
		for _, gap := range gaps {
			if gap.Path == DocumentIndexPackPath && gap.Pointer == fmt.Sprintf("/documents/%d/%s", index, pointer) {
				found = true
				if gap.Code != code || !strings.Contains(gap.Detail, want) {
					t.Errorf("gap at %s = %s %q, want %s mentioning %q", gap.Pointer, gap.Code, gap.Detail, code, want)
				}
			}
		}
		if !found {
			t.Errorf("no gap for /documents/%d/%s in %+v", index, pointer, gaps)
		}
	}
}

func TestCollectStagesVerifiedFiles(t *testing.T) {
	pdf := []byte("%PDF-1.4 policy content")
	client := &fakeClient{
		snapshot: snapshotWith(locktivity.Document{
			DocumentID:       "doc-1",
			Name:             "Information security policy",
			Source:           "github",
			VersionID:        "ver-1",
			VersionNumber:    3,
			Checksum:         "source-checksum",
			ArtifactPath:     "documents/information-security-policy.pdf",
			ArtifactChecksum: digestOf(pdf),
			FileURL:          "https://files.example/policy",
		}),
		files: map[string][]byte{"https://files.example/policy": pdf},
	}

	output, gaps, outputDir := collect(t, client)
	if len(gaps) != 0 {
		t.Fatalf("unexpected gaps: %+v", gaps)
	}

	staged := output.Files[0]
	if staged.RelPath != "documents/doc-1/information-security-policy.pdf" {
		t.Errorf("unexpected rel path: %s", staged.RelPath)
	}
	if staged.PackPath != "artifacts/documents/doc-1/information-security-policy.pdf" {
		t.Errorf("unexpected pack path: %s", staged.PackPath)
	}
	if staged.DisplayName != "Information security policy" {
		t.Errorf("unexpected display name: %s", staged.DisplayName)
	}
	got, err := os.ReadFile(filepath.Join(outputDir, staged.RelPath))
	if err != nil || string(got) != string(pdf) {
		t.Errorf("staged file mismatch: %v", err)
	}
	if strings.Join(client.ops, ",") != locktivity.FileDownload.Name {
		t.Errorf("download operations = %v", client.ops)
	}
}

func TestCollectIndexOmitsFileURLs(t *testing.T) {
	pdf := []byte("content")
	client := &fakeClient{
		snapshot: snapshotWith(locktivity.Document{
			DocumentID:       "doc-1",
			Name:             "Policy",
			Source:           "upload",
			VersionID:        "ver-1",
			ArtifactPath:     "documents/policy.pdf",
			ArtifactChecksum: digestOf(pdf),
			FileURL:          "https://files.example/secret-signed-url",
		}),
		files: map[string][]byte{"https://files.example/secret-signed-url": pdf},
	}

	output, _, _ := collect(t, client)

	if output.Index.SnapshotID != "snap-1" || output.Index.Digest != "manifest-digest" {
		t.Errorf("unexpected index metadata: %+v", output.Index)
	}
	documents := output.Index.Documents
	raw, err := json.Marshal(documents[0])
	if err != nil {
		t.Fatalf("marshal index entry: %v", err)
	}
	if strings.Contains(string(raw), "secret-signed-url") || strings.Contains(string(raw), "file_url") || strings.Contains(string(raw), "text_url") {
		t.Errorf("index must not carry fetch URLs, got %s", raw)
	}
}

func TestCollectStagesNativeSourceForRenderedDocuments(t *testing.T) {
	rendered := []byte("%PDF-1.4 rendered")
	source := []byte("# Access control policy")
	client := &fakeClient{
		snapshot: snapshotWith(locktivity.Document{
			DocumentID:          "doc-1",
			Name:                "Access control policy",
			Source:              "github",
			VersionID:           "ver-1",
			Checksum:            digestOf(source),
			ByteSize:            int64(len(source)),
			ContentType:         "text/markdown",
			ArtifactPath:        "documents/access-control-policy.pdf",
			ArtifactChecksum:    digestOf(rendered),
			ArtifactContentType: "application/pdf",
			ArtifactByteSize:    int64(len(rendered)),
			FileURL:             "https://files.example/rendered",
			SourcePath:          "documents/access-control-policy.md",
			SourceURL:           "https://files.example/source",
			DocumentType:        "evidencepack/document@v1",
		}),
		files: map[string][]byte{
			"https://files.example/rendered": rendered,
			"https://files.example/source":   source,
		},
	}

	output, _, outputDir := collect(t, client)

	sourceFile := output.Files[1]
	if sourceFile.RelPath != "documents/doc-1/access-control-policy.md" {
		t.Errorf("unexpected source rel path: %s", sourceFile.RelPath)
	}
	if sourceFile.DisplayName != "Access control policy · Source" {
		t.Errorf("unexpected source display name: %s", sourceFile.DisplayName)
	}
	got, err := os.ReadFile(filepath.Join(outputDir, sourceFile.RelPath))
	if err != nil || string(got) != string(source) {
		t.Errorf("staged source mismatch: %v", err)
	}

	entry := output.Index.Documents[0]
	if entry.File == nil || entry.File.ByteSize != int64(len(rendered)) || entry.File.ContentType != "application/pdf" {
		t.Errorf("file pointer should describe the rendering: %+v", entry.File)
	}
	if entry.SourceFile == nil {
		t.Fatal("expected a source_file pointer")
	}
	if entry.SourceFile.Path != "artifacts/documents/doc-1/access-control-policy.md" {
		t.Errorf("unexpected source path: %s", entry.SourceFile.Path)
	}
	if entry.SourceFile.Digest != "sha256:"+digestOf(source) {
		t.Errorf("unexpected source digest: %s", entry.SourceFile.Digest)
	}
	if entry.SourceFile.ContentType != "text/markdown" || entry.SourceFile.ByteSize != int64(len(source)) {
		t.Errorf("source pointer should describe the native file: %+v", entry.SourceFile)
	}

	metadata := output.Metadata[0]
	if metadata.Body["file_path"] != "artifacts/documents/doc-1/access-control-policy.pdf" {
		t.Errorf("unexpected file back-ref: %v", metadata.Body["file_path"])
	}
	if metadata.Body["source_path"] != "artifacts/documents/doc-1/access-control-policy.md" {
		t.Errorf("unexpected source back-ref: %v", metadata.Body["source_path"])
	}
	if strings.Join(client.ops, ",") != locktivity.FileDownload.Name+","+locktivity.SourceDownload.Name {
		t.Errorf("download operations = %v", client.ops)
	}
}

func TestCollectLeavesOutATamperedSourceWithItsDocument(t *testing.T) {
	rendered := []byte("%PDF-1.4 rendered")
	pdf := []byte("%PDF-1.4 other")
	client := &fakeClient{
		snapshot: snapshotWith(
			locktivity.Document{
				DocumentID:       "doc-1",
				Name:             "Policy",
				Checksum:         strings.Repeat("0", 64),
				ArtifactPath:     "documents/policy.pdf",
				ArtifactChecksum: digestOf(rendered),
				FileURL:          "https://files.example/rendered",
				SourcePath:       "documents/policy.md",
				SourceURL:        "https://files.example/source",
			},
			locktivity.Document{
				DocumentID: "doc-2", Name: "Other", ArtifactPath: "documents/other.pdf",
				ArtifactChecksum: digestOf(pdf), FileURL: "https://files.example/other",
			},
		),
		files: map[string][]byte{
			"https://files.example/rendered": rendered,
			"https://files.example/source":   []byte("tampered source"),
			"https://files.example/other":    pdf,
		},
	}

	output, gaps, outputDir := collect(t, client)

	expectLeftOut(t, output, gaps, 0, componentsdk.CodeInvalidResponse, "checksum mismatch", "file", "source_file")
	if _, err := os.Stat(filepath.Join(outputDir, "documents/doc-1/policy.pdf")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the left-out document's rendering should be removed from staging, stat err=%v", err)
	}
	if len(output.Files) != 1 || output.Files[0].PackPath != "artifacts/documents/doc-2/other.pdf" {
		t.Errorf("files = %+v, want only the other document", output.Files)
	}
	for _, path := range []string{"artifacts/documents/doc-1/policy.pdf", "artifacts/documents/doc-1/policy.md"} {
		found := false
		for _, gap := range gaps {
			found = found || (gap.Path == path && gap.Pointer == "")
		}
		if !found {
			t.Errorf("no gap for the artifact %s", path)
		}
	}
}

func TestCollectLeavesOutADocumentWithAnUnsafeSourcePath(t *testing.T) {
	rendered := []byte("%PDF-1.4 rendered")
	client := &fakeClient{
		snapshot: snapshotWith(locktivity.Document{
			DocumentID:       "doc-1",
			Name:             "Policy",
			Checksum:         digestOf([]byte("src")),
			ArtifactPath:     "documents/policy.pdf",
			ArtifactChecksum: digestOf(rendered),
			FileURL:          "https://files.example/rendered",
			SourcePath:       "../escape.md",
			SourceURL:        "https://files.example/source",
		}),
		files: map[string][]byte{
			"https://files.example/rendered": rendered,
			"https://files.example/source":   []byte("src"),
		},
	}

	output, gaps, _ := collect(t, client)

	expectLeftOut(t, output, gaps, 0, componentsdk.CodeInvalidResponse, "unsafe source path", "file", "source_file")
	if len(client.ops) != 0 {
		t.Errorf("a document with an unsafe path should download nothing, got %v", client.ops)
	}
}

func TestCollectLeavesOutADocumentThatFailsItsChecksum(t *testing.T) {
	client := &fakeClient{
		snapshot: snapshotWith(locktivity.Document{
			DocumentID:       "doc-1",
			Name:             "Tampered",
			VersionID:        "ver-1",
			ArtifactPath:     "documents/tampered.pdf",
			ArtifactChecksum: strings.Repeat("0", 64),
			FileURL:          "https://files.example/tampered",
		}),
		files: map[string][]byte{"https://files.example/tampered": []byte("other bytes")},
	}

	output, gaps, outputDir := collect(t, client)

	expectLeftOut(t, output, gaps, 0, componentsdk.CodeInvalidResponse, "checksum mismatch", "file")
	if _, statErr := os.Stat(filepath.Join(outputDir, "documents/doc-1/tampered.pdf")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed checksum should remove staged file, stat err=%v", statErr)
	}
	if len(output.Files) != 0 {
		t.Errorf("files = %+v, want none", output.Files)
	}
}

func TestCollectRemovesStagedFileAfterDownloadError(t *testing.T) {
	client := &fakeClient{
		snapshot: snapshotWith(locktivity.Document{
			DocumentID:       "doc-1",
			Name:             "Interrupted",
			ArtifactPath:     "documents/interrupted.pdf",
			ArtifactChecksum: strings.Repeat("0", 64),
			FileURL:          "https://files.example/interrupted",
		}),
		files: map[string][]byte{"https://files.example/interrupted": []byte("partial bytes")},
		errs:  map[string]error{"https://files.example/interrupted": &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}},
	}

	output, gaps, outputDir := collect(t, client)

	expectLeftOut(t, output, gaps, 0, componentsdk.CodeVendorError, "connection reset", "file")
	if _, statErr := os.Stat(filepath.Join(outputDir, "documents/doc-1/interrupted.pdf")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed download should remove staged file, stat err=%v", statErr)
	}
}

func TestCollectLeavesOutADocumentWithoutAChecksum(t *testing.T) {
	client := &fakeClient{
		snapshot: snapshotWith(locktivity.Document{
			DocumentID:   "doc-1",
			Name:         "No checksum",
			VersionID:    "ver-1",
			ArtifactPath: "documents/no-checksum.pdf",
			FileURL:      "https://files.example/x",
		}),
		files: map[string][]byte{"https://files.example/x": []byte("bytes")},
	}

	output, gaps, _ := collect(t, client)

	expectLeftOut(t, output, gaps, 0, componentsdk.CodeInvalidResponse, "no usable checksum", "file")
}

func TestCollectLeavesOutDocumentsWithUnsafeArtifactPaths(t *testing.T) {
	for _, path := range []string{"../escape.pdf", "/abs/path.pdf", ""} {
		client := &fakeClient{
			snapshot: snapshotWith(locktivity.Document{
				DocumentID:       "doc-1",
				Name:             "Evil",
				VersionID:        "ver-1",
				ArtifactPath:     path,
				ArtifactChecksum: digestOf([]byte("x")),
				FileURL:          "https://files.example/evil",
			}),
			files: map[string][]byte{"https://files.example/evil": []byte("x")},
		}

		output, gaps, _ := collect(t, client)

		expectLeftOut(t, output, gaps, 0, componentsdk.CodeInvalidResponse, "unsafe artifact path", "file")
		if len(gaps) != 1 {
			t.Errorf("artifact path %q: gaps = %+v, want only the index pointer's", path, gaps)
		}
	}
}

func TestCollectRecordsDocumentsWithNoFile(t *testing.T) {
	client := &fakeClient{
		snapshot: snapshotWith(locktivity.Document{
			DocumentID:   "doc-2",
			Name:         "Fileless",
			Source:       "upload",
			Warnings:     []string{"No file available; document skipped"},
			DocumentType: "evidencepack/document@v1",
		}),
	}

	output, gaps, _ := collect(t, client)

	if len(output.Files) != 0 || len(output.Metadata) != 0 || len(gaps) != 0 {
		t.Errorf("a document with no file is an answer, not a gap: files %+v, metadata %+v, gaps %+v", output.Files, output.Metadata, gaps)
	}
	raw, err := json.Marshal(output.Index.Documents[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"file":null`, `"source_file":null`, `"text":null`, `"metadata":null`, `"version_number":null`, `"document_type":"evidencepack/document@v1"`, `"warnings":["No file available; document skipped"]`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("entry %s lacks %s", raw, want)
		}
	}
}

func TestCollectStagesVerifiedText(t *testing.T) {
	pdf := []byte("%PDF-1.4 policy")
	text := []byte(`{"document_id":"doc-1","chunks":[{"chunk_id":0,"page":1,"text":"body"}]}`)
	client := &fakeClient{
		snapshot: snapshotWith(locktivity.Document{
			DocumentID:       "doc-1",
			Name:             "Acme SOC 2",
			VersionID:        "ver-1",
			ArtifactPath:     "documents/acme-soc2.pdf",
			ArtifactChecksum: digestOf(pdf),
			FileURL:          "https://files.example/pdf",
			TextURL:          "https://files.example/text",
			TextChecksum:     digestOf(text),
		}),
		files: map[string][]byte{
			"https://files.example/pdf":  pdf,
			"https://files.example/text": text,
		},
	}

	output, _, outputDir := collect(t, client)

	if len(output.Files) != 2 {
		t.Fatalf("expected pdf and text staged, got %d files", len(output.Files))
	}
	textFile := output.Files[1]
	if textFile.RelPath != "documents/doc-1/text.json" {
		t.Errorf("unexpected text rel path: %s", textFile.RelPath)
	}
	if textFile.Schema != DocumentTextSchema {
		t.Errorf("unexpected text schema: %s", textFile.Schema)
	}
	if textFile.DisplayName != "Acme SOC 2 · Text" {
		t.Errorf("unexpected text display name: %s", textFile.DisplayName)
	}
	got, err := os.ReadFile(filepath.Join(outputDir, textFile.RelPath))
	if err != nil || string(got) != string(text) {
		t.Errorf("staged text mismatch: %v", err)
	}

	entry := output.Index.Documents[0]
	if entry.Text == nil || entry.Text.Path != "artifacts/documents/doc-1/text.json" {
		t.Errorf("unexpected text pointer: %+v", entry.Text)
	}
	if entry.Text == nil || entry.Text.Digest != "sha256:"+digestOf(text) {
		t.Errorf("unexpected text digest: %+v", entry.Text)
	}
	if strings.Join(client.ops, ",") != locktivity.FileDownload.Name+","+locktivity.TextDownload.Name {
		t.Errorf("download operations = %v", client.ops)
	}
}

func TestCollectLeavesOutADocumentWhoseTextFailsItsChecksum(t *testing.T) {
	pdf := []byte("%PDF-1.4 policy")
	client := &fakeClient{
		snapshot: snapshotWith(locktivity.Document{
			DocumentID:       "doc-1",
			Name:             "Acme SOC 2",
			ArtifactPath:     "documents/acme-soc2.pdf",
			ArtifactChecksum: digestOf(pdf),
			FileURL:          "https://files.example/pdf",
			TextURL:          "https://files.example/text",
			TextChecksum:     strings.Repeat("0", 64),
			DocumentType:     "evidencepack/soc2-report@v1",
		}),
		files: map[string][]byte{
			"https://files.example/pdf":  pdf,
			"https://files.example/text": []byte("tampered"),
		},
	}

	output, gaps, _ := collect(t, client)

	expectLeftOut(t, output, gaps, 0, componentsdk.CodeInvalidResponse, "checksum mismatch", "file", "text", "metadata")
	if len(output.Files) != 0 || len(output.Metadata) != 0 {
		t.Errorf("the left-out document's artifacts should not be emitted: files %+v, metadata %+v", output.Files, output.Metadata)
	}
	if entry := output.Index.Documents[0]; entry.DocumentType == nil || *entry.DocumentType != "evidencepack/soc2-report@v1" {
		t.Errorf("the left-out document should keep its type, got %+v", entry)
	}
}

func TestCollectEmitsTypedMetadata(t *testing.T) {
	pdf := []byte("%PDF-1.4 policy")
	text := []byte(`{"chunks":[]}`)
	client := &fakeClient{
		snapshot: snapshotWith(locktivity.Document{
			DocumentID:       "doc-1",
			Name:             "Acme SOC 2",
			ArtifactPath:     "documents/acme-soc2.pdf",
			ArtifactChecksum: digestOf(pdf),
			FileURL:          "https://files.example/pdf",
			TextURL:          "https://files.example/text",
			TextChecksum:     digestOf(text),
			DocumentType:     "evidencepack/soc2-report@v1",
			Metadata: map[string]any{
				"auditor":       "Prescient Assurance",
				"report_type":   "type_ii",
				"document_id":   "spoofed",
				"file_path":     "artifacts/spoofed.pdf",
				"access_token":  "TOKEN_METADATA_CANARY",
				"callback_url":  "https://example.com/callback?signature=CALLBACK_SIGNATURE_CANARY&safe=1",
				"source_url":    "SOURCE_METADATA_CANARY",
				"unknown_field": "not part of schema",
			},
			Provenance: map[string]any{
				"auditor":      map[string]any{"chunk_id": 0, "page": 1, "quote": "Report of Prescient Assurance", "file_url": "SIGNED_URL_CANARY", "source_url": "SOURCE_PROVENANCE_CANARY"},
				"access_token": map[string]any{"quote": "TOKEN_PROVENANCE_CANARY"},
			},
		}),
		files: map[string][]byte{
			"https://files.example/pdf":  pdf,
			"https://files.example/text": text,
		},
	}

	output, _, outputDir := collect(t, client)

	if len(output.Metadata) != 1 {
		t.Fatalf("expected one metadata artifact, got %d", len(output.Metadata))
	}
	metadata := output.Metadata[0]
	if metadata.PackPath != "artifacts/documents/doc-1/metadata.json" || metadata.RelPath != "documents/doc-1/metadata.json" {
		t.Errorf("unexpected metadata paths: %s staged at %s", metadata.PackPath, metadata.RelPath)
	}
	if metadata.Schema != "evidencepack/soc2-report@v1" {
		t.Errorf("unexpected metadata schema: %s", metadata.Schema)
	}
	if metadata.DisplayName != "Acme SOC 2 · Metadata" {
		t.Errorf("unexpected metadata display name: %s", metadata.DisplayName)
	}
	fields, ok := metadata.Body["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested metadata fields, got %+v", metadata.Body)
	}
	if fields["auditor"] != "Prescient Assurance" || fields["report_type"] != "type_ii" {
		t.Errorf("compliance fields missing: %+v", fields)
	}
	if metadata.Body["document_id"] != "doc-1" {
		t.Errorf("identity must win over snapshot metadata keys, got %v", metadata.Body["document_id"])
	}
	if metadata.Body["file_path"] != "artifacts/documents/doc-1/acme-soc2.pdf" {
		t.Errorf("unexpected file back-ref: %v", metadata.Body["file_path"])
	}
	if fields["document_id"] != "spoofed" || fields["file_path"] != "artifacts/spoofed.pdf" || fields["unknown_field"] != "not part of schema" {
		t.Errorf("safe source metadata should remain namespaced, got %+v", fields)
	}
	callback, ok := fields["callback_url"].(string)
	if !ok || !strings.Contains(callback, "signature=[REDACTED]") {
		t.Errorf("signed URL query value should be redacted, got %v", fields["callback_url"])
	}
	for _, blocked := range []string{"access_token", "source_url"} {
		if _, ok := fields[blocked]; ok {
			t.Errorf("metadata field %q should not be emitted: %+v", blocked, fields)
		}
	}
	if metadata.Body["text_path"] != "artifacts/documents/doc-1/text.json" {
		t.Errorf("unexpected text back-ref: %v", metadata.Body["text_path"])
	}
	provenance, ok := metadata.Body["provenance"].(map[string]any)
	if !ok {
		t.Errorf("provenance missing: %+v", metadata.Body)
	}
	if auditorProvenance, ok := provenance["auditor"].(map[string]any); !ok || auditorProvenance["quote"] != "Report of Prescient Assurance" {
		t.Errorf("unexpected auditor provenance: %+v", provenance)
	}
	rawMetadata, err := os.ReadFile(filepath.Join(outputDir, filepath.FromSlash(metadata.RelPath)))
	if err != nil {
		t.Fatalf("reading the staged metadata file: %v", err)
	}
	var staged map[string]any
	if err := json.Unmarshal(rawMetadata, &staged); err != nil || staged["document_id"] != "doc-1" || staged["file_path"] != metadata.Body["file_path"] {
		t.Errorf("the staged metadata file does not hold the body: %s (err %v)", rawMetadata, err)
	}
	for _, forbidden := range []string{"TOKEN_METADATA_CANARY", "TOKEN_PROVENANCE_CANARY", "SIGNED_URL_CANARY", "CALLBACK_SIGNATURE_CANARY", "SOURCE_METADATA_CANARY", "SOURCE_PROVENANCE_CANARY"} {
		if strings.Contains(string(rawMetadata), forbidden) {
			t.Fatalf("metadata leaked %q: %s", forbidden, rawMetadata)
		}
	}

	entry := output.Index.Documents[0]
	if entry.DocumentType == nil || *entry.DocumentType != "evidencepack/soc2-report@v1" {
		t.Errorf("unexpected index document_type: %v", entry.DocumentType)
	}
	if entry.Metadata == nil || entry.Metadata.Path != "artifacts/documents/doc-1/metadata.json" {
		t.Errorf("unexpected index metadata pointer: %+v", entry.Metadata)
	}
}

func TestCollectWithoutSubstrateFields(t *testing.T) {
	pdf := []byte("%PDF-1.4 policy")
	client := &fakeClient{
		snapshot: snapshotWith(locktivity.Document{
			DocumentID:       "doc-1",
			Name:             "Policy",
			ArtifactPath:     "documents/policy.pdf",
			ArtifactChecksum: digestOf(pdf),
			FileURL:          "https://files.example/pdf",
		}),
		files: map[string][]byte{"https://files.example/pdf": pdf},
	}

	output, _, _ := collect(t, client)

	if len(output.Files) != 1 || len(output.Metadata) != 0 {
		t.Fatalf("expected pdf only, got %d files and %d metadata", len(output.Files), len(output.Metadata))
	}
	entry := output.Index.Documents[0]
	if entry.Text != nil || entry.Metadata != nil || entry.DocumentType != nil {
		t.Errorf("entry should have no text, metadata, or document_type without substrate fields: %+v", entry)
	}
}

func TestCollectArtifactsDoNotLeakEphemeralSnapshotData(t *testing.T) {
	pdf := []byte("%PDF-1.4 policy")
	source := []byte("# Policy")
	text := []byte(`{"chunks":[]}`)
	client := &fakeClient{
		snapshot: snapshotWith(locktivity.Document{
			DocumentID:       "doc-1",
			Name:             "Policy",
			Source:           "upload",
			Checksum:         digestOf(source),
			ArtifactPath:     "documents/policy.pdf",
			ArtifactChecksum: digestOf(pdf),
			FileURL:          "https://files.example/pdf?signature=PDF_SIGNED_URL_CANARY",
			SourcePath:       "documents/policy.md",
			SourceURL:        "https://files.example/source?signature=SOURCE_SIGNED_URL_CANARY",
			TextURL:          "https://files.example/text?signature=TEXT_SIGNED_URL_CANARY",
			TextChecksum:     digestOf(text),
			DocumentType:     "evidencepack/document@v1",
			Metadata: map[string]any{
				"classification": "public",
				"file_url":       "PDF_METADATA_CANARY",
				"source_url":     "SOURCE_METADATA_CANARY",
				"text_url":       "TEXT_METADATA_CANARY",
			},
			Provenance: map[string]any{
				"classification": map[string]any{"source_url": "SOURCE_PROVENANCE_CANARY"},
			},
		}),
		files: map[string][]byte{
			"https://files.example/pdf?signature=PDF_SIGNED_URL_CANARY":       pdf,
			"https://files.example/source?signature=SOURCE_SIGNED_URL_CANARY": source,
			"https://files.example/text?signature=TEXT_SIGNED_URL_CANARY":     text,
		},
	}

	output, _, _ := collect(t, client)

	raw, err := json.Marshal(struct {
		Index    DocumentIndex      `json:"index"`
		Metadata []MetadataArtifact `json:"metadata"`
		Files    []StagedFile       `json:"files"`
	}{Index: output.Index, Metadata: output.Metadata, Files: output.Files})
	if err != nil {
		t.Fatalf("marshal output: %v", err)
	}
	for _, forbidden := range []string{
		"PDF_SIGNED_URL_CANARY",
		"SOURCE_SIGNED_URL_CANARY",
		"TEXT_SIGNED_URL_CANARY",
		"PDF_METADATA_CANARY",
		"SOURCE_METADATA_CANARY",
		"SOURCE_PROVENANCE_CANARY",
		"TEXT_METADATA_CANARY",
		"file_url",
		"source_url",
		"text_url",
	} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("collector output leaked %q: %s", forbidden, raw)
		}
	}
}

func TestCollectLeavesOutADocumentWhoseMetadataPathIsTaken(t *testing.T) {
	pdfA, pdfB := []byte("%PDF-1.4 a"), []byte("%PDF-1.4 b")
	client := &fakeClient{
		snapshot: snapshotWith(
			locktivity.Document{
				DocumentID: "dup", Name: "First", ArtifactPath: "documents/a.pdf",
				ArtifactChecksum: digestOf(pdfA), FileURL: "https://files.example/a",
				DocumentType: "evidencepack/document@v1",
			},
			locktivity.Document{
				DocumentID: "dup", Name: "Second", ArtifactPath: "documents/b.pdf",
				ArtifactChecksum: digestOf(pdfB), FileURL: "https://files.example/b",
				DocumentType: "evidencepack/document@v1",
			},
		),
		files: map[string][]byte{
			"https://files.example/a": pdfA,
			"https://files.example/b": pdfB,
		},
	}

	output, gaps, _ := collect(t, client)

	expectLeftOut(t, output, gaps, 1, componentsdk.CodeInvalidResponse, "duplicate staged path", "file", "metadata")
	if output.Index.Documents[0].Metadata == nil || len(output.Metadata) != 1 {
		t.Errorf("the first document should keep its metadata: %+v", output.Index.Documents[0])
	}
	for _, gap := range gaps {
		if gap.Path != DocumentIndexPackPath {
			t.Errorf("a path the first document holds must not get a gap: %+v", gap)
		}
	}
}

func TestCollectLeavesOutAFileNamedLikeItsMetadata(t *testing.T) {
	pdf := []byte("%PDF-1.4 sneaky")
	client := &fakeClient{
		snapshot: snapshotWith(locktivity.Document{
			DocumentID: "doc-1", Name: "Sneaky", ArtifactPath: "documents/metadata.json",
			ArtifactChecksum: digestOf(pdf), FileURL: "https://files.example/sneaky",
			DocumentType: "evidencepack/document@v1",
		}),
		files: map[string][]byte{"https://files.example/sneaky": pdf},
	}

	output, gaps, _ := collect(t, client)

	expectLeftOut(t, output, gaps, 0, componentsdk.CodeInvalidResponse, "duplicate staged path", "file", "metadata")
}

func TestCollectLeavesOutDocumentsWithUnsafeIDs(t *testing.T) {
	pdf := []byte("content")
	for _, id := range []string{"..", ".", "a/b", ""} {
		client := &fakeClient{
			snapshot: snapshotWith(locktivity.Document{
				DocumentID:       id,
				Name:             "Doc",
				ArtifactPath:     "documents/policy.pdf",
				ArtifactChecksum: digestOf(pdf),
				FileURL:          "https://files.example/policy",
			}),
			files: map[string][]byte{"https://files.example/policy": pdf},
		}

		output, gaps, _ := collect(t, client)

		expectLeftOut(t, output, gaps, 0, componentsdk.CodeInvalidResponse, "unsafe document id", "file")
		if len(output.Files) != 0 {
			t.Errorf("document id %q: files = %+v, want none", id, output.Files)
		}
	}
}

func TestCollectLeavesOutTheSecondOfTwoDocumentsWithOnePath(t *testing.T) {
	pdf := []byte("content")
	client := &fakeClient{
		snapshot: snapshotWith(
			locktivity.Document{
				DocumentID:       "dup",
				Name:             "First",
				ArtifactPath:     "documents/policy.pdf",
				ArtifactChecksum: digestOf(pdf),
				FileURL:          "https://files.example/a",
			},
			locktivity.Document{
				DocumentID:       "dup",
				Name:             "Second",
				ArtifactPath:     "documents/policy.pdf",
				ArtifactChecksum: digestOf(pdf),
				FileURL:          "https://files.example/b",
			},
		),
		files: map[string][]byte{
			"https://files.example/a": pdf,
			"https://files.example/b": pdf,
		},
	}

	output, gaps, _ := collect(t, client)

	expectLeftOut(t, output, gaps, 1, componentsdk.CodeInvalidResponse, "duplicate staged path", "file")
	if output.Index.Documents[0].File == nil || len(output.Files) != 1 {
		t.Errorf("the first document should ship: %+v", output.Index.Documents[0])
	}
}

func TestCollectUnderAnotherNamePointsAtThatNamesFolder(t *testing.T) {
	pdf := []byte("%PDF-1.4 policy")
	text := []byte(`{"chunks":[]}`)
	client := &fakeClient{
		snapshot: snapshotWith(locktivity.Document{
			DocumentID:       "doc-1",
			Name:             "Acme SOC 2",
			ArtifactPath:     "documents/acme-soc2.pdf",
			ArtifactChecksum: digestOf(pdf),
			FileURL:          "https://files.example/pdf",
			TextURL:          "https://files.example/text",
			TextChecksum:     digestOf(text),
			DocumentType:     "evidencepack/soc2-report@v1",
		}),
		files: map[string][]byte{
			"https://files.example/pdf":  pdf,
			"https://files.example/text": text,
		},
	}
	output, err := Collect(context.Background(), Config{
		RunKey:   "run-1",
		Stager:   dirStager{dir: t.TempDir()},
		Recorder: &componentsdk.Recorder{},
		Name:     "policies",
	}, client)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	entry := output.Index.Documents[0]
	if entry.File == nil || entry.File.Path != "artifacts/policies/doc-1/acme-soc2.pdf" {
		t.Errorf("file pointer = %+v, want artifacts/policies/doc-1/acme-soc2.pdf", entry.File)
	}
	if entry.Text == nil || entry.Text.Path != "artifacts/policies/doc-1/text.json" {
		t.Errorf("text pointer = %+v, want artifacts/policies/doc-1/text.json", entry.Text)
	}
	if entry.Metadata == nil || entry.Metadata.Path != "artifacts/policies/doc-1/metadata.json" {
		t.Errorf("metadata pointer = %+v, want artifacts/policies/doc-1/metadata.json", entry.Metadata)
	}
	if got := output.Metadata[0].Body["file_path"]; got != "artifacts/policies/doc-1/acme-soc2.pdf" {
		t.Errorf("metadata file_path = %v, want artifacts/policies/doc-1/acme-soc2.pdf", got)
	}
	for _, a := range output.Artifacts()[1:] {
		if !strings.HasPrefix(a.Path, "artifacts/policies/doc-1/") {
			t.Errorf("artifact %s is outside the run's folder", a.Path)
		}
	}
}
