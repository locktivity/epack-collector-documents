# Examples

## Basic Usage

### Locktivity-Managed Pipeline (Recommended)

When you add the Documents collector to a pipeline, Locktivity generates the
workflow and `epack.yaml`. The generated collector section looks like:

```yaml
stream: myorg/production

credential_sets:
  locktivity_documents: "credset_9f8e7d"

collectors:
  documents:
    source: locktivity/epack-collector-documents@^0.1
    credentials:
      - locktivity_documents
```

That's all that's needed: the pipeline run includes the documents you selected
for it, authenticated with a short-lived token issued for the run.

### Your Own CI (Client Credentials)

Outside GitHub Actions, the collector authenticates with an API application's
client credentials and names its pipeline explicitly. Locktivity generates
this configuration for CLI pipelines:

```yaml
stream: myorg/production

collectors:
  documents:
    source: locktivity/epack-collector-documents@^0.1
    config:
      pipeline_id: "pl_9f8e7d"
    secrets:
      - LOCKTIVITY_CLIENT_ID
      - LOCKTIVITY_CLIENT_SECRET
      - LOCKTIVITY_RUN_KEY
      - GITHUB_RUN_ID
      - GITHUB_RUN_ATTEMPT
```

Then run:

```bash
export LOCKTIVITY_CLIENT_ID="..."
export LOCKTIVITY_CLIENT_SECRET="..."
export LOCKTIVITY_RUN_KEY="$YOUR_CI_RUN_ID"
epack collect
```

The application needs the **Collect documents** permission. See
[Configuration](configuration.md) for setup instructions and what each
variable does.

## Sample Output

The index at `artifacts/documents.json`:

```json
{
  "snapshot_id": "snap_1a2b3c",
  "pipeline_id": "pl_9f8e7d",
  "run_key": "gha-1234-1",
  "captured_at": "2026-07-08T12:00:00Z",
  "digest": "sha256:...",
  "documents": [
    {
      "document_id": "doc_4f2a9c",
      "name": "Acme SOC 2 Type II 2025",
      "source": "upload",
      "version_number": 3,
      "document_type": "evidencepack/soc2-report@v1",
      "file": {
        "path": "artifacts/documents/doc_4f2a9c/acme-soc2-2025.pdf",
        "digest": "sha256:...",
        "content_type": "application/pdf",
        "byte_size": 1048576
      },
      "text": {
        "path": "artifacts/documents/doc_4f2a9c/text.json",
        "digest": "sha256:..."
      },
      "metadata": {
        "path": "artifacts/documents/doc_4f2a9c/metadata.json"
      },
      "warnings": []
    }
  ]
}
```

## Looking at What Landed in a Pack

```bash
# List the documents in a pack
unzip -l evidence-*.epack | grep documents

# See each document's name, type, and where its files landed
unzip -p evidence-*.epack artifacts/documents.json | jq '.documents[] | {name, document_type, file: .file.path, text: .text.path}'

# Read a document's extracted details (auditor, dates, and where each was found)
unzip -p evidence-*.epack artifacts/documents/<id>/metadata.json | jq
```
