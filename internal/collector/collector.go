// Package collector builds document artifacts from captured snapshots.
package collector

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/locktivity/epack-collector-documents/internal/limits"
	"github.com/locktivity/epack-collector-documents/internal/locktivity"
	"github.com/locktivity/epack-collector-documents/internal/redact"
	"github.com/locktivity/epack/componentsdk"
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
	// Recorder takes a gap for each document Collect leaves out.
	Recorder *componentsdk.Recorder
	// Name is the name the run is configured under, as
	// componentsdk.CollectorContext.Name gives it. The pack paths written
	// into the index and each metadata file use it.
	Name       string
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
	if c.Recorder == nil {
		return errors.New("a recorder is required")
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

// MetadataArtifact is a document's typed metadata, staged as a JSON file in
// the document's folder beside its other files. Its schema ID is the
// document type.
type MetadataArtifact struct {
	// RelPath is the staged file's name relative to the staging directory.
	RelPath     string
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
}

// Artifacts lists the artifacts to emit: the index, then each staged file
// and metadata artifact.
func (o *Output) Artifacts() []componentsdk.CollectedArtifact {
	artifacts := []componentsdk.CollectedArtifact{
		componentsdk.JSONArtifact(DocumentIndexPackPath, o.Index, componentsdk.ArtifactMeta{
			Schema:      DocumentIndexSchema,
			DisplayName: "Documents index",
			Description: "The documents included in this pack, with a pointer to each.",
		}),
	}
	for _, file := range o.Files {
		artifacts = append(artifacts, componentsdk.FileArtifact(file.PackPath, file.RelPath, componentsdk.ArtifactMeta{
			DisplayName: file.DisplayName,
			Schema:      file.Schema,
		}))
	}
	for _, metadata := range o.Metadata {
		artifacts = append(artifacts, componentsdk.FileArtifact(metadata.PackPath, metadata.RelPath, componentsdk.ArtifactMeta{
			Schema:      metadata.Schema,
			DisplayName: metadata.DisplayName,
		}))
	}
	return artifacts
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

// DocumentIndexEntry is one document row in the index. A field that does
// not apply to the document is null.
type DocumentIndexEntry struct {
	DocumentID    string                   `json:"document_id"`
	Name          string                   `json:"name"`
	Source        string                   `json:"source"`
	Warnings      []string                 `json:"warnings"`
	VersionNumber *int                     `json:"version_number"`
	DocumentType  *string                  `json:"document_type"`
	File          *DocumentFilePointer     `json:"file"`
	SourceFile    *DocumentFilePointer     `json:"source_file"`
	Text          *DocumentTextPointer     `json:"text"`
	Metadata      *DocumentMetadataPointer `json:"metadata"`

	// leftOut names the pointers left out of the entry because the
	// document's files could not be collected. The collector result has a
	// gap for each.
	leftOut []string
}

// MarshalJSON writes the entry without the pointers in leftOut.
func (e DocumentIndexEntry) MarshalJSON() ([]byte, error) {
	type entry DocumentIndexEntry
	raw, err := json.Marshal(entry(e))
	if err != nil || len(e.leftOut) == 0 {
		return raw, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	for _, key := range e.leftOut {
		delete(fields, key)
	}
	return json.Marshal(fields)
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
	Download(ctx context.Context, op componentsdk.Operation, url string, dst io.Writer) (string, int64, error)
}

// Collect builds document pack output from a snapshot. It fails only when
// the snapshot cannot be taken. A document whose files cannot be downloaded
// and verified is left out of the pack as a whole, with gaps recorded for
// its artifacts and its index pointers, and the rest are still collected.
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
	entries := make([]DocumentIndexEntry, 0, len(snapshot.Documents))
	for i, doc := range snapshot.Documents {
		entries = append(entries, run.collectDocument(ctx, i, doc))
	}
	run.output.Index = documentIndex(snapshot, entries)

	status(cfg, run.summary())
	return run.output, nil
}

type collectionRun struct {
	cfg         Config
	client      SnapshotClient
	output      *Output
	seen        map[string]bool
	total       int64
	included    int
	withoutFile []string
	leftOut     []string
}

// packPath is the pack path of the staged file at relPath, as the run
// writes it under its configured name. See componentsdk.RunPath.
func (r *collectionRun) packPath(relPath string) string {
	return componentsdk.RunPath(collectorName, r.cfg.Name, artifactPackPath(relPath))
}

func newCollectionRun(cfg Config, client SnapshotClient, total int) *collectionRun {
	return &collectionRun{
		cfg:    cfg,
		client: client,
		output: &Output{},
		seen:   make(map[string]bool),
		total:  int64(total),
	}
}

// documentPlan is where a document's files go, as staging-relative paths.
// A path is empty when the document has no such file.
type documentPlan struct {
	file, source, text, metadata string
}

func (p documentPlan) paths() []string {
	var out []string
	for _, rel := range []string{p.file, p.source, p.text, p.metadata} {
		if rel != "" {
			out = append(out, rel)
		}
	}
	return out
}

// documentArtifacts is what one collected document adds to the pack.
type documentArtifacts struct {
	files      []StagedFile
	metadata   *MetadataArtifact
	file       *DocumentFilePointer
	sourceFile *DocumentFilePointer
	text       *DocumentTextPointer
}

func (r *collectionRun) collectDocument(ctx context.Context, index int, doc locktivity.Document) DocumentIndexEntry {
	entry := indexEntry(doc)
	if doc.FileURL == "" { // LINT-ALLOW: branch only, fetch URL is never emitted
		r.withoutFile = append(r.withoutFile, doc.Name)
		return entry
	}

	progress(r.cfg, int64(index+1), r.total, doc.Name)
	plan, err := r.plan(doc)
	if err == nil {
		var staged documentArtifacts
		if staged, err = r.stage(ctx, doc, plan); err == nil {
			r.include(&entry, staged)
			return entry
		}
	}
	r.leaveOut(index, doc, plan, &entry, err)
	return entry
}

// plan checks the snapshot's paths for a document and reserves where its
// files go in the pack.
func (r *collectionRun) plan(doc locktivity.Document) (documentPlan, error) {
	file, err := stagePath(doc)
	if err != nil {
		return documentPlan{}, err
	}
	p := documentPlan{file: file}
	if doc.SourceURL != "" { // LINT-ALLOW: branch only, fetch URL is never emitted
		if doc.SourcePath == "" || filepath.IsAbs(doc.SourcePath) || !filepath.IsLocal(doc.SourcePath) {
			return documentPlan{}, unusableManifest("unsafe source path %q in snapshot manifest", doc.SourcePath)
		}
		p.source = documentArtifactRelPath(doc.DocumentID, filepath.Base(doc.SourcePath))
	}
	if doc.TextURL != "" { // LINT-ALLOW: branch only, fetch URL is never emitted
		p.text = documentTextRelPath(doc.DocumentID)
	}
	if doc.DocumentType != "" {
		p.metadata = documentMetadataRelPath(doc.DocumentID)
	}

	paths := p.paths()
	for i, rel := range paths {
		if r.seen[rel] || slices.Contains(paths[:i], rel) {
			return documentPlan{}, unusableManifest("duplicate staged path %q", rel)
		}
	}
	for _, rel := range paths {
		r.seen[rel] = true
	}
	return p, nil
}

// stage downloads and verifies a document's files and builds its metadata.
// When any step fails it removes the files it staged.
func (r *collectionRun) stage(ctx context.Context, doc locktivity.Document, plan documentPlan) (documentArtifacts, error) {
	var out documentArtifacts
	var staged []string
	fail := func(err error) (documentArtifacts, error) {
		for _, name := range staged {
			if removeErr := os.Remove(name); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("removing staged file: %w", removeErr))
			}
		}
		return documentArtifacts{}, err
	}
	fetch := func(op componentsdk.Operation, url, relPath, expected, displayName, schema string) (StagedFile, string, error) {
		file, digest, name, err := fetchVerified(ctx, r.cfg.Stager, r.client, op, url, relPath, expected, displayName, schema)
		if err != nil {
			return StagedFile{}, "", err
		}
		file.PackPath = r.packPath(file.RelPath)
		staged = append(staged, name)
		out.files = append(out.files, file)
		return file, digest, nil
	}

	file, digest, err := fetch(locktivity.FileDownload, doc.FileURL, plan.file, cmp.Or(doc.ArtifactChecksum, doc.Checksum), doc.Name, "") // LINT-ALLOW: download-only, fetch URL is never emitted
	if err != nil {
		return fail(err)
	}
	out.file = &DocumentFilePointer{
		Path:        file.PackPath,
		Digest:      "sha256:" + digest,
		ContentType: doc.ArtifactContentType,
		ByteSize:    artifactByteSize(doc),
	}

	var sourcePackPath string
	if plan.source != "" {
		source, digest, err := fetch(locktivity.SourceDownload, doc.SourceURL, plan.source, doc.Checksum, doc.Name+" · Source", "") // LINT-ALLOW: download-only, fetch URL is never emitted
		if err != nil {
			return fail(fmt.Errorf("source: %w", err))
		}
		sourcePackPath = source.PackPath
		out.sourceFile = &DocumentFilePointer{
			Path:        source.PackPath,
			Digest:      "sha256:" + digest,
			ContentType: doc.ContentType,
			ByteSize:    doc.ByteSize,
		}
	}

	var textPackPath string
	if plan.text != "" {
		text, digest, err := fetch(locktivity.TextDownload, doc.TextURL, plan.text, doc.TextChecksum, doc.Name+" · Text", DocumentTextSchema) // LINT-ALLOW: download-only, fetch URL is never emitted
		if err != nil {
			return fail(fmt.Errorf("text: %w", err))
		}
		textPackPath = text.PackPath
		out.text = &DocumentTextPointer{Path: text.PackPath, Digest: "sha256:" + digest}
	}

	if plan.metadata != "" {
		metadata := metadataArtifact(doc, file.PackPath, sourcePackPath, textPackPath)
		name, filename, err := stageJSON(r.cfg.Stager, plan.metadata, metadata.Body)
		if err != nil {
			return fail(fmt.Errorf("metadata: %w", err))
		}
		staged = append(staged, filename)
		metadata.RelPath = name
		metadata.PackPath = r.packPath(name)
		out.metadata = &metadata
	}
	return out, nil
}

// stageJSON writes body as a JSON file at relPath in staging. It returns the
// file's staged name and its path on disk.
func stageJSON(stager Stager, relPath string, body any) (string, string, error) {
	file, name, err := stager.StageFile(relPath)
	if err != nil {
		return "", "", fmt.Errorf("staging %q: %w", relPath, err)
	}
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	err = enc.Encode(body)
	if closeErr := file.Close(); err == nil && closeErr != nil {
		err = fmt.Errorf("closing staged file: %w", closeErr)
	}
	if err != nil {
		_, _, _, err = removeFailedStagedFile(file.Name(), err)
		return "", "", err
	}
	return name, file.Name(), nil
}

func (r *collectionRun) include(entry *DocumentIndexEntry, staged documentArtifacts) {
	r.included++
	r.output.Files = append(r.output.Files, staged.files...)
	entry.File = staged.file
	entry.SourceFile = staged.sourceFile
	entry.Text = staged.text
	if staged.metadata != nil {
		r.output.Metadata = append(r.output.Metadata, *staged.metadata)
		entry.Metadata = &DocumentMetadataPointer{Path: staged.metadata.PackPath}
	}
}

// leaveOut keeps a document's entry in the index without its pointers and
// records why: a gap for each pointer the entry would have had, and one for
// each artifact whose place in the pack was reserved.
func (r *collectionRun) leaveOut(index int, doc locktivity.Document, plan documentPlan, entry *DocumentIndexEntry, err error) {
	r.leftOut = append(r.leftOut, doc.Name)
	for _, rel := range plan.paths() {
		r.cfg.Recorder.NotCollected(componentsdk.Location{Path: r.packPath(rel)}, err)
	}
	pointers := []string{"file"}
	if doc.SourceURL != "" { // LINT-ALLOW: branch only, fetch URL is never emitted
		pointers = append(pointers, "source_file")
	}
	if doc.TextURL != "" { // LINT-ALLOW: branch only, fetch URL is never emitted
		pointers = append(pointers, "text")
	}
	if doc.DocumentType != "" {
		pointers = append(pointers, "metadata")
	}
	for _, field := range pointers {
		r.cfg.Recorder.NotCollected(componentsdk.Location{
			Path:    DocumentIndexPackPath,
			Pointer: fmt.Sprintf("/documents/%d/%s", index, field),
		}, err)
	}
	entry.leftOut = pointers
}

func artifactByteSize(doc locktivity.Document) int64 {
	if doc.ArtifactByteSize > 0 {
		return doc.ArtifactByteSize
	}
	return doc.ByteSize
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
	if doc.DocumentType != "" {
		entry.DocumentType = &doc.DocumentType
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
		return "", unusableManifest("unsafe document id %q in snapshot manifest", doc.DocumentID)
	}
	if doc.ArtifactPath == "" || filepath.IsAbs(doc.ArtifactPath) || !filepath.IsLocal(doc.ArtifactPath) {
		return "", unusableManifest("unsafe artifact path %q in snapshot manifest", doc.ArtifactPath)
	}
	return documentArtifactRelPath(doc.DocumentID, filepath.Base(doc.ArtifactPath)), nil
}

func isSafeSegment(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, `/\`)
}

// unusableManifest is a snapshot entry the collector cannot stage safely.
func unusableManifest(format string, args ...any) error {
	return componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf(format, args...))
}

// fetchVerified stages a download only after checksum verification succeeds,
// and returns the staged file's name for removal.
func fetchVerified(ctx context.Context, stager Stager, client SnapshotClient, op componentsdk.Operation, url, relPath, expected, displayName, schema string) (StagedFile, string, string, error) {
	if len(expected) != limits.SHA256HexChars {
		return StagedFile{}, "", "", unusableManifest("snapshot manifest has no usable checksum")
	}

	file, name, err := stager.StageFile(relPath)
	if err != nil {
		return StagedFile{}, "", "", fmt.Errorf("staging %q: %w", relPath, err)
	}

	digest, _, err := client.Download(ctx, op, url, file)
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
		// Short prefixes, since redaction hides long hex strings in gap details.
		return removeFailedStagedFile(file.Name(), componentsdk.CodeError(componentsdk.CodeInvalidResponse,
			fmt.Errorf("checksum mismatch: downloaded sha256 %s, manifest expects %s", digest[:12], expected[:12])))
	}

	return StagedFile{
		RelPath:     name,
		PackPath:    artifactPackPath(name),
		DisplayName: displayName,
		Schema:      schema,
	}, digest, file.Name(), nil
}

func removeFailedStagedFile(filename string, cause error) (StagedFile, string, string, error) {
	if err := os.Remove(filename); err != nil && !errors.Is(err, os.ErrNotExist) {
		cause = errors.Join(cause, fmt.Errorf("removing failed staged file: %w", err))
	}
	return StagedFile{}, "", "", cause
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

func (r *collectionRun) summary() string {
	msg := fmt.Sprintf("Included %d of %d documents, each verified against its checksum", r.included, r.total)
	if len(r.withoutFile) > 0 {
		msg += ". No file yet: " + strings.Join(r.withoutFile, ", ")
	}
	if len(r.leftOut) > 0 {
		msg += ". Left out, as their files could not be downloaded and verified: " + strings.Join(r.leftOut, ", ")
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
