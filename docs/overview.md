# Documents Collector

The Documents collector adds your Locktivity evidence documents to evidence
packs, so your policies and reports travel with the rest of your evidence.

You manage documents in Locktivity: upload them, or connect a source like
GitHub or Google Drive. When a pipeline runs, this collector adds the
documents you selected for that pipeline to the pack.

## What It Collects

Each run adds a folder per document under `artifacts/documents/<id>/`,
plus one index:

- **Document files**: each document's file as you manage it in Locktivity. An
  uploaded PDF or spreadsheet ships as itself. A document linked from a source
  like GitHub or Google Drive ships as a rendered PDF plus the original source
  file, so the pack carries both the readable copy and the exact bytes the
  version was recorded from.
- **Extracted text**: the document's text in searchable chunks, anchored to
  pages (PDFs) or sheets and rows (spreadsheets), so checks and searches can
  cite the exact passage.
- **Document details**: what Locktivity found in the document. For a SOC 2
  report that includes the audit period, the auditor, and the report type,
  each with the passage it came from.
- **Document index** (`artifacts/documents.json`): every document with its
  name, source, and version, pointing to that document's files.

Each file is verified against its recorded checksum before it is packed.

## Use Cases

- **Audit evidence**: hand an auditor one bundle where the SOC 2 report and
  the policies sit next to the machine evidence
- **Customer security reviews**: answer document requests with versioned,
  checked files instead of email attachments
- **Content checks**: the extracted text lets validation profiles check that a
  policy covers a topic, citing the exact passage

## How It Works

1. The collector requests the document snapshot for this pipeline run from
   Locktivity. The first request captures the set; retries of the same run
   get the identical set back.
2. It downloads each document file and its extracted text over pre-signed
   URLs, and verifies every download against the checksum Locktivity
   recorded. A mismatch fails the run rather than packing the file.
3. It writes each document's details file from the captured snapshot.
4. Everything is staged into per-document folders, the index is built, and
   the output is wrapped in the epack collector protocol envelope.

## Output Layout

```
artifacts/
  documents.json                      # the index
  documents/
    doc_4f2a9c/
      acme-soc2-2025.pdf              # the document, ready to open
      text.json                       # extracted text with citations
      metadata.json                   # extracted details with citations
    doc_7b3e1f/
      access-policy.pdf               # rendered from the linked source
      access-policy.md                # the original source file
      text.json
```

Field-level schemas for the index and text artifacts live in
[`schema/`](schema/).

## Index Reference

Each entry in `documents.json` describes one document:

| Field | What It Tells You |
|-------|-------------------|
| `name`, `source`, `version_number` | Which document this is, where it lives, and which version shipped. |
| `document_type` | What kind of document Locktivity recognized, such as a SOC 2 report or a penetration test. |
| `file`, `source_file`, `text`, `metadata` | Where each of the document's files landed in the pack, with a digest for each downloaded file. `source_file` appears when the shipped file is a rendering of a linked source. |
| `warnings` | Anything incomplete: a document with no file yet, or text not extracted yet. |
| `captured_at`, `run_key`, `digest` (top level) | When the document set was captured, the run it belongs to, and the integrity hash of the whole set. |

## What's Included

Which documents a pipeline carries is decided in Locktivity, on the pipeline's
Documents collector: all of your documents, or a chosen subset. The collector
follows that selection, and there's nothing to configure here.

## Authentication

On a Locktivity-managed pipeline, a short-lived token is issued automatically
for each run, so no long-lived secret is stored in your CI settings. In your
own CI, the collector exchanges an API application's client credentials for a
short-lived token on each run.

See [Configuration](configuration.md) for setup instructions.
