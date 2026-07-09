# epack-collector-documents

An [epack](https://github.com/locktivity/epack) collector that adds an
account's Locktivity evidence documents to evidence packs. It fetches the
document snapshot Locktivity captures for a pipeline run, verifies each file
against its checksum, and writes the files plus a `documents.json` manifest
into the pack.

End-user documentation (what the collector does, how to configure it, and
examples) lives in [`docs/`](docs/) and is published to the collector
registry. **This README is for working on the collector itself.**

## Layout

- `cmd/epack-collector-documents`: entry point: parses config, resolves the
  run key, classifies errors for the SDK, and wires staged artifacts into the
  emitted pack.
- `internal/collector`: collection orchestration, document artifact path
  layout, download + checksum verification, metadata artifact assembly, and
  staging of files for the pack.
- `internal/limits`: shared timeout, retry, size, redirect, and checksum
  limits. Security-sensitive bounds should live here instead of being scattered
  through the codebase.
- `internal/locktivity`: HTTP client for the management API: token exchange,
  endpoint policy, snapshot requests, and SSRF-guarded, size-bounded file
  downloads.
- `internal/redact`: shared redaction helpers for server error messages and
  untrusted metadata/provenance before they enter logs or emitted artifacts.
- `docs/schema`: JSON Schema contracts for collector-owned artifacts.

## Building and testing

```bash
make build   # build the binary
make test    # go test -race ./...
make lint    # golangci-lint (matches CI)
```

## Running against custom endpoints

For local end-to-end testing against a compatible non-production API, expose the
API over HTTPS and point epack at the local binary. Custom endpoint URLs must
not include userinfo, query strings, or fragments.

```yaml
collectors:
  documents:
    binary: "/absolute/path/to/epack-collector-documents"
    config:
      insecure_endpoint: "https://api.example.test"
    secrets:
      - LOCKTIVITY_DOCUMENTS_TOKEN
```

```bash
export LOCKTIVITY_DOCUMENTS_TOKEN="<test token accepted by the custom API>"
epack lock && epack collect
```

To exercise the client-credentials path instead, omit
`LOCKTIVITY_DOCUMENTS_TOKEN`, supply `LOCKTIVITY_CLIENT_ID` and
`LOCKTIVITY_CLIENT_SECRET`, set `pipeline_id`, and point the exchange at a
trusted HTTPS auth endpoint:

```yaml
collectors:
  documents:
    binary: "/absolute/path/to/epack-collector-documents"
    config:
      pipeline_id: "<pipeline id>"
      insecure_endpoint: "https://api.example.test"
      insecure_auth_endpoint: "https://app.example.test"
    secrets:
      - LOCKTIVITY_CLIENT_ID
      - LOCKTIVITY_CLIENT_SECRET
```

## Releasing

Tag the repo with a semantic version, such as `v0.1.0`. The release workflow
builds SLSA-attested binaries from the tag.

## License

Apache 2.0
