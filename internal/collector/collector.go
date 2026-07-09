// Package collector builds document artifacts from captured snapshots.
package collector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/locktivity/epack-collector-documents/internal/limits"
	"github.com/locktivity/epack-collector-documents/internal/locktivity"
	"github.com/locktivity/epack-collector-documents/internal/redact"
)

// Stager is the SDK file-staging surface Collect needs.
type Stager interface {
	StageFile(relPath string) (*os.File, string, error)
}

// Config drives one collection run.
type Config struct {
	// PipelineID is set for client-credentials runs.
	PipelineID string
	RunKey     string
	Stager     Stager
	OnStatus   func(string)
	OnProgress func(current, total int64, message string)
}

// Validate checks run-local requirements.
func (c Config) Validate() error {
	if c.RunKey == "" {
		return errors.New("run_key is required")
	}
	if c.Stager == nil {
		return errors.New("a stager is required")
	}
	return nil
}

const (
	// DocumentIndexSchema is the documents manifest schema.
	DocumentIndexSchema = "evidencepack/document-index@v1"

	// DocumentTextSchema is the extracted text schema.
	DocumentTextSchema = "evidencepack/document-text@v1"
)

// StagedFile is a downloaded document file staged for pack inclusion.
type StagedFile struct {
	RelPath     string
	PackPath    string
	DisplayName string
	Schema      string
}

// MetadataArtifact is a document's typed metadata, emitted as a JSON artifact.
type MetadataArtifact struct {
	PackPath    string
	Schema      string
	DisplayName string
	Body        map[string]any
}

// Output is the result of a collection run.
type Output struct {
	// Index never includes the pre-signed URLs used to fetch files.
	Index    DocumentIndex
	Files    []StagedFile
	Metadata []MetadataArtifact
	Skipped  []string
}

// DocumentIndex is the evidencepack/document-index@v1 artifact.
type DocumentIndex struct {
	SnapshotID string               `json:"snapshot_id"`
	PipelineID string               `json:"pipeline_id"`
	RunKey     string               `json:"run_key"`
	Digest     string               `json:"digest"`
	CapturedAt string               `json:"captured_at"`
	Documents  []DocumentIndexEntry `json:"documents"`
}

// DocumentIndexEntry is one document row in the index.
type DocumentIndexEntry struct {
	DocumentID    string                   `json:"document_id"`
	Name          string                   `json:"name"`
	Source        string                   `json:"source"`
	Warnings      []string                 `json:"warnings"`
	VersionNumber *int                     `json:"version_number,omitempty"`
	DocumentType  string                   `json:"document_type,omitempty"`
	File          *DocumentFilePointer     `json:"file,omitempty"`
	SourceFile    *DocumentFilePointer     `json:"source_file,omitempty"`
	Text          *DocumentTextPointer     `json:"text,omitempty"`
	Metadata      *DocumentMetadataPointer `json:"metadata,omitempty"`
}

// DocumentFilePointer points from the index to a staged document file.
type DocumentFilePointer struct {
	Path        string `json:"path"`
	Digest      string `json:"digest"`
	ContentType string `json:"content_type"`
	ByteSize    int64  `json:"byte_size"`
}

// DocumentTextPointer points from the index to the staged text artifact.
type DocumentTextPointer struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

// DocumentMetadataPointer points from the index to the typed metadata artifact.
type DocumentMetadataPointer struct {
	Path string `json:"path"`
}

// SnapshotClient is the API surface Collect needs.
type SnapshotClient interface {
	CreateSnapshot(ctx context.Context, pipelineID, runKey string) (*locktivity.Snapshot, error)
	Download(ctx context.Context, url string, dst io.Writer) (string, int64, error)
}

// Collect builds document pack output from a snapshot.
func Collect(ctx context.Context, cfg Config, client SnapshotClient) (*Output, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	status(cfg, "Requesting document snapshot...")
	snapshot, err := client.CreateSnapshot(ctx, cfg.PipelineID, cfg.RunKey)
	if err != nil {
		return nil, err
	}

	run := newCollectionRun(cfg, client, len(snapshot.Documents))
	if err := run.collectDocuments(ctx, snapshot.Documents); err != nil {
		return nil, err
	}
	run.output.Index = documentIndex(snapshot, run.entries)

	status(cfg, summary(run.included, run.output.Skipped))
	return run.output, nil
}

type collectionRun struct {
	cfg      Config
	client   SnapshotClient
	output   *Output
	entries  []DocumentIndexEntry
	seen     map[string]bool
	included int
	total    int64
}

func newCollectionRun(cfg Config, client SnapshotClient, total int) *collectionRun {
	return &collectionRun{
		cfg:     cfg,
		client:  client,
		output:  &Output{},
		entries: make([]DocumentIndexEntry, 0, total),
		seen:    make(map[string]bool),
		total:   int64(total),
	}
}

func (r *collectionRun) collectDocuments(ctx context.Context, docs []locktivity.Document) error {
	for i, doc := range docs {
		if err := r.collectDocument(ctx, i, doc); err != nil {
			return err
		}
	}
	return nil
}

func (r *collectionRun) collectDocument(ctx context.Context, index int, doc locktivity.Document) error {
	entry := indexEntry(doc)
	if doc.FileURL == "" { // LINT-ALLOW: branch only, fetch URL is never emitted
		r.output.Skipped = append(r.output.Skipped, doc.Name)
		r.entries = append(r.entries, entry)
		return nil
	}

	staged, digest, err := r.collectFile(ctx, index, doc)
	if err != nil {
		return err
	}
	entry.File = &DocumentFilePointer{
		Path:        staged.PackPath,
		Digest:      "sha256:" + digest,
		ContentType: doc.ArtifactContentType,
		ByteSize:    artifactByteSize(doc),
	}

	sourcePackPath, err := r.collectSource(ctx, doc, &entry)
	if err != nil {
		return err
	}
	textPackPath, err := r.collectText(ctx, doc, &entry)
	if err != nil {
		return err
	}
	if err := r.collectMetadata(doc, staged.PackPath, sourcePackPath, textPackPath, &entry); err != nil {
		return err
	}

	r.entries = append(r.entries, entry)
	return nil
}

func (r *collectionRun) collectFile(ctx context.Context, index int, doc locktivity.Document) (StagedFile, string, error) {
	relPath, err := stagePath(doc)
	if err != nil {
		return StagedFile{}, "", fmt.Errorf("document %q: %w", doc.Name, err)
	}
	if err := r.reservePath(doc.Name, relPath); err != nil {
		return StagedFile{}, "", err
	}

	progress(r.cfg, int64(index+1), r.total, doc.Name)
	expected := doc.ArtifactChecksum
	if expected == "" {
		expected = doc.Checksum
	}
	staged, digest, err := fetchVerified(ctx, r.cfg, r.client, doc.FileURL, relPath, expected, doc.Name, "") // LINT-ALLOW: download-only, fetch URL is never emitted
	if err != nil {
		return StagedFile{}, "", fmt.Errorf("document %q: %w", doc.Name, err)
	}
	r.included++
	r.output.Files = append(r.output.Files, staged)
	return staged, digest, nil
}

// collectSource stages the native source file, when present.
func (r *collectionRun) collectSource(ctx context.Context, doc locktivity.Document, entry *DocumentIndexEntry) (string, error) {
	if doc.SourceURL == "" { // LINT-ALLOW: branch only, fetch URL is never emitted
		return "", nil
	}
	if doc.SourcePath == "" || filepath.IsAbs(doc.SourcePath) || !filepath.IsLocal(doc.SourcePath) {
		return "", fmt.Errorf("document %q: unsafe source path %q in snapshot manifest", doc.Name, doc.SourcePath)
	}

	sourceRel := documentArtifactRelPath(doc.DocumentID, filepath.Base(doc.SourcePath))
	if err := r.reservePath(doc.Name, sourceRel); err != nil {
		return "", err
	}

	staged, digest, err := fetchVerified(ctx, r.cfg, r.client, doc.SourceURL, sourceRel, doc.Checksum, doc.Name+" · Source", "") // LINT-ALLOW: download-only, fetch URL is never emitted
	if err != nil {
		return "", fmt.Errorf("document %q source: %w", doc.Name, err)
	}
	r.output.Files = append(r.output.Files, staged)
	entry.SourceFile = &DocumentFilePointer{
		Path:        staged.PackPath,
		Digest:      "sha256:" + digest,
		ContentType: doc.ContentType,
		ByteSize:    doc.ByteSize,
	}
	return staged.PackPath, nil
}

// artifactByteSize returns the shipped file size.
func artifactByteSize(doc locktivity.Document) int64 {
	if doc.ArtifactByteSize > 0 {
		return doc.ArtifactByteSize
	}
	return doc.ByteSize
}

func (r *collectionRun) collectText(ctx context.Context, doc locktivity.Document, entry *DocumentIndexEntry) (string, error) {
	if doc.TextURL == "" { // LINT-ALLOW: branch only, fetch URL is never emitted
		return "", nil
	}

	textRel := documentTextRelPath(doc.DocumentID)
	if err := r.reservePath(doc.Name, textRel); err != nil {
		return "", err
	}

	textStaged, textDigest, err := fetchVerified(ctx, r.cfg, r.client, doc.TextURL, textRel, doc.TextChecksum, doc.Name+" · Text", DocumentTextSchema) // LINT-ALLOW: download-only, fetch URL is never emitted
	if err != nil {
		return "", fmt.Errorf("document %q text: %w", doc.Name, err)
	}
	r.output.Files = append(r.output.Files, textStaged)
	entry.Text = &DocumentTextPointer{
		Path:   textStaged.PackPath,
		Digest: "sha256:" + textDigest,
	}
	return textStaged.PackPath, nil
}

func (r *collectionRun) collectMetadata(doc locktivity.Document, filePackPath, sourcePackPath, textPackPath string, entry *DocumentIndexEntry) error {
	if doc.DocumentType == "" {
		return nil
	}

	entry.DocumentType = doc.DocumentType
	metaRel := documentMetadataRelPath(doc.DocumentID)
	if err := r.reservePath(doc.Name, metaRel); err != nil {
		return err
	}

	metadata := metadataArtifact(doc, filePackPath, sourcePackPath, textPackPath)
	r.output.Metadata = append(r.output.Metadata, metadata)
	entry.Metadata = &DocumentMetadataPointer{Path: metadata.PackPath}
	return nil
}

func (r *collectionRun) reservePath(docName, relPath string) error {
	if r.seen[relPath] {
		return fmt.Errorf("document %q: duplicate staged path %q", docName, relPath)
	}
	r.seen[relPath] = true
	return nil
}

func indexEntry(doc locktivity.Document) DocumentIndexEntry {
	warnings := doc.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	entry := DocumentIndexEntry{
		DocumentID: doc.DocumentID,
		Name:       doc.Name,
		Source:     doc.Source,
		Warnings:   warnings,
	}
	if doc.VersionID != "" {
		entry.VersionNumber = &doc.VersionNumber
	}
	return entry
}

func documentIndex(snapshot *locktivity.Snapshot, documents []DocumentIndexEntry) DocumentIndex {
	return DocumentIndex{
		SnapshotID: snapshot.ID,
		PipelineID: snapshot.PipelineID,
		RunKey:     snapshot.RunKey,
		Digest:     snapshot.Digest,
		CapturedAt: snapshot.CapturedAt,
		Documents:  documents,
	}
}

func stagePath(doc locktivity.Document) (string, error) {
	if !isSafeSegment(doc.DocumentID) {
		return "", fmt.Errorf("unsafe document id %q in snapshot manifest", doc.DocumentID)
	}
	if doc.ArtifactPath == "" || filepath.IsAbs(doc.ArtifactPath) || !filepath.IsLocal(doc.ArtifactPath) {
		return "", fmt.Errorf("unsafe artifact path %q in snapshot manifest", doc.ArtifactPath)
	}
	return documentArtifactRelPath(doc.DocumentID, filepath.Base(doc.ArtifactPath)), nil
}

func isSafeSegment(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, `/\`)
}

// fetchVerified stages a download only after checksum verification succeeds.
func fetchVerified(ctx context.Context, cfg Config, client SnapshotClient, url, relPath, expected, displayName, schema string) (StagedFile, string, error) {
	if len(expected) != limits.SHA256HexChars {
		return StagedFile{}, "", errors.New("snapshot manifest has no usable checksum")
	}

	file, name, err := cfg.Stager.StageFile(relPath)
	if err != nil {
		return StagedFile{}, "", fmt.Errorf("staging %q: %w", relPath, err)
	}

	digest, _, err := client.Download(ctx, url, file)
	closeErr := file.Close()
	if err != nil {
		if closeErr != nil {
			err = errors.Join(err, fmt.Errorf("closing staged file: %w", closeErr))
		}
		return removeFailedStagedFile(file.Name(), err)
	}
	if closeErr != nil {
		return removeFailedStagedFile(file.Name(), fmt.Errorf("closing staged file: %w", closeErr))
	}

	if digest != expected {
		return removeFailedStagedFile(file.Name(), fmt.Errorf("checksum mismatch: downloaded %s, manifest expects %s", digest, expected))
	}

	return StagedFile{
		RelPath:     name,
		PackPath:    artifactPackPath(name),
		DisplayName: displayName,
		Schema:      schema,
	}, digest, nil
}

func removeFailedStagedFile(filename string, cause error) (StagedFile, string, error) {
	if err := os.Remove(filename); err != nil && !errors.Is(err, os.ErrNotExist) {
		cause = errors.Join(cause, fmt.Errorf("removing failed staged file: %w", err))
	}
	return StagedFile{}, "", cause
}

// metadataArtifact keeps untrusted fields below metadata/provenance.
func metadataArtifact(doc locktivity.Document, filePackPath, sourcePackPath, textPackPath string) MetadataArtifact {
	body := map[string]any{
		"document_id": doc.DocumentID,
		"name":        doc.Name,
		"filename":    path.Base(filePackPath),
		"file_path":   filePackPath,
	}
	if sourcePackPath != "" {
		body["source_path"] = sourcePackPath
	}
	if textPackPath != "" {
		body["text_path"] = textPackPath
	}
	fields := redact.Map(doc.Metadata)
	if len(fields) > 0 {
		body["metadata"] = fields
	}
	provenance := redact.Map(doc.Provenance)
	if len(provenance) > 0 {
		body["provenance"] = provenance
	}

	return MetadataArtifact{
		PackPath:    artifactPackPath(documentMetadataRelPath(doc.DocumentID)),
		Schema:      doc.DocumentType,
		DisplayName: doc.Name + " · Metadata",
		Body:        body,
	}
}

func summary(included int, skipped []string) string {
	msg := fmt.Sprintf("Included %d documents, each verified against its checksum", included)
	if len(skipped) > 0 {
		msg += fmt.Sprintf(". Skipped %d with no file yet: %s", len(skipped), strings.Join(skipped, ", "))
	}
	return msg
}

func status(cfg Config, message string) {
	if cfg.OnStatus != nil {
		cfg.OnStatus(message)
	}
}

func progress(cfg Config, current, total int64, message string) {
	if cfg.OnProgress != nil {
		cfg.OnProgress(current, total, message)
	}
}
