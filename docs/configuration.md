# Documents Collector Configuration

## Requirements

- epack v0.2.0 or newer. On older versions the collector stops with a message
  asking you to upgrade.

## Authentication Setup

### Locktivity-Managed Pipeline

When you add the Documents collector to a pipeline in Locktivity, the pipeline
generates the collector configuration. At runtime, the pipeline credential
provides a token for the collector:

```yaml
credential_sets:
  locktivity_documents: "<credential-set-id>"

collectors:
  documents:
    source: locktivity/epack-collector-documents@^0.1
    credentials:
      - locktivity_documents
```

### Your Own CI (Client Credentials)

For a pipeline you run yourself, configure the collector with an API
application's client id and client secret. The collector uses them to request an
access token for the run.

#### Step 1: Create an API Application

1. In Locktivity, create an API application for your CI
2. Grant it the **Collect documents** permission
3. Copy the client id and client secret into your CI's secret store

#### Step 2: Configure epack

```yaml
collectors:
  documents:
    source: locktivity/epack-collector-documents@^0.1
    config:
      pipeline_id: "<pipeline-id>"
    secrets:
      - LOCKTIVITY_CLIENT_ID
      - LOCKTIVITY_CLIENT_SECRET
      - LOCKTIVITY_RUN_KEY
      - GITHUB_RUN_ID
      - GITHUB_RUN_ATTEMPT
```

Only variables listed under `secrets` reach the collector.

#### Step 3: Export the Run Identity

Run identity groups retries of the same run so they produce the identical set
of documents; without it, every invocation includes the latest documents as a
fresh set.

```bash
export LOCKTIVITY_RUN_KEY="$YOUR_CI_RUN_ID"
```

In GitHub Actions, skip this step: keep `GITHUB_RUN_ID` and
`GITHUB_RUN_ATTEMPT` in the `secrets` list and the collector uses them.

## Configuration Options

| Option | Required | Description |
|--------|----------|-------------|
| `pipeline_id` | In your own CI | Which pipeline's document selection to include. On a Locktivity-managed pipeline the token already identifies the pipeline, so this is omitted; with client credentials it is required, and Locktivity fills it in when it generates the configuration. |
| `run_key` | No | Groups retries of the same run. On a Locktivity-managed pipeline this comes from the workflow run's verified identity automatically; in your own CI, export `LOCKTIVITY_RUN_KEY` per run instead. Set this option directly only for one-off runs outside any CI. |
| `insecure_endpoint` | No | Advanced HTTPS endpoint override for the documents API. The `insecure_` name is an explicit acknowledgement that API traffic is redirected away from the default endpoint. |
| `insecure_auth_endpoint` | No | Advanced HTTPS endpoint override for the client-credentials token exchange. Use only a trusted endpoint; the collector sends `LOCKTIVITY_CLIENT_SECRET` there. |

### Advanced Endpoint Overrides

Endpoint overrides redirect API traffic away from the default Locktivity
service. Use them only with endpoints you control or explicitly trust.
Custom endpoint URLs must not include userinfo, query strings, or fragments.
Plain HTTP endpoint overrides are always rejected.

```yaml
collectors:
  documents:
    source: locktivity/epack-collector-documents@^0.1
    config:
      pipeline_id: "<pipeline-id>"
      insecure_endpoint: "https://api.example.com"
      insecure_auth_endpoint: "https://app.example.com"
    secrets:
      - LOCKTIVITY_CLIENT_ID
      - LOCKTIVITY_CLIENT_SECRET
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `LOCKTIVITY_DOCUMENTS_TOKEN` | Short-lived token issued per run on managed pipelines. You never set this yourself. |
| `LOCKTIVITY_CLIENT_ID` | API application client id, for your own CI. |
| `LOCKTIVITY_CLIENT_SECRET` | API application client secret, for your own CI. |
| `LOCKTIVITY_RUN_KEY` | Per-run identity exported by your CI, so retries stay identical. |
| `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT` | GitHub Actions run identity, used automatically when listed under `secrets`. |

## Troubleshooting

### Exit codes

| Exit | Code | When |
|------|------|------|
| 0 | | The run collected, even if some documents were left out |
| 1 | `invalid_response` | Locktivity's answer to the token or snapshot request was not what the collector expects |
| 1 | `too_large` | The snapshot from Locktivity is over the collector's 32 MB limit |
| 2 | `config_invalid` | No credentials, no `pipeline_id` with client credentials, an endpoint override that is not HTTPS, an epack too old for file artifacts, a pipeline without the Documents collector, or an account without the Documents feature or the pipeline |
| 3 | `auth_failed` | Locktivity rejected the token or the client credentials |
| 3 | `permission_denied` | The credential lacks the **Collect documents** permission |
| 4 | `rate_limited`, `vendor_error`, `timeout` | Locktivity or its token endpoint could not be reached or kept failing |

### A configuration error asking you to upgrade on startup

Your epack is older than v0.2.0. Upgrade it.

### An authentication error

Locktivity rejected the token or the client credentials (`auth_failed`), or
the credential lacks the snapshot permission (`permission_denied`). Both exit
with code 3. On a managed pipeline, check the pipeline's Documents credential
in Locktivity. In your own CI, check `LOCKTIVITY_CLIENT_ID` and
`LOCKTIVITY_CLIENT_SECRET` and the application's **Collect documents**
permission. Missing credentials are a configuration error instead, with exit
code 2.

### "pipeline has no documents collector"

The pipeline in Locktivity doesn't have the Documents collector enabled. Add
it in the pipeline's collectors step.

### A checksum mismatch

A downloaded document didn't match what Locktivity recorded. The collector
leaves that document out of the pack, records an `invalid_response` gap for it
in `artifacts/documents.collector-result.json`, and includes the rest. Re-run,
and contact support if it persists rather than bypassing the check.

### A document is missing from the pack

A document that has no file uploaded yet doesn't fail the run: it's listed in
`artifacts/documents.document-index.json` with `file` set to `null` and a
warning, and named in the run summary. Upload a file for it in Locktivity and
the next run includes it.

A document whose files could not be downloaded is listed without its file
fields, and `artifacts/documents.collector-result.json` has a gap for each
with the reason, such as `vendor_error` when the download kept failing. A
file over 100 MB is left out with a `too_large` gap, since a pack holds at
most 100 MB per file.
