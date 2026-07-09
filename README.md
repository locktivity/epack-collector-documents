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
make test-dev # go test -tags dev ./...
make lint    # golangci-lint (matches CI)
```

## Running against loopback development endpoints

For local end-to-end testing against a compatible non-production API on
loopback, build the dev-tagged binary and point epack at it with `binary`.
Release builds reject endpoint overrides; dev builds allow only HTTP or HTTPS
endpoints whose host resolves entirely to loopback, with no userinfo, query
string, or fragment.

The simplest path is to supply a test token directly instead of relying on the
brokered runtime credential:

```bash
make build-dev
```

```yaml
collectors:
  documents:
    binary: "/absolute/path/to/epack-collector-documents-dev"
    config:
      insecure_endpoint: "http://127.0.0.1:3000"
    secrets:
      - LOCKTIVITY_DOCUMENTS_TOKEN
```

```bash
export LOCKTIVITY_DOCUMENTS_TOKEN="<test token accepted by the loopback API>"
epack lock && epack collect
```

Download-URL SSRF checks are relaxed only in dev-tagged builds when
`insecure_endpoint` is plain HTTP and resolves entirely to loopback. Release
builds, HTTPS loopback endpoints, and non-loopback endpoints keep those checks
enforced.

To exercise the client-credentials path instead, omit
`LOCKTIVITY_DOCUMENTS_TOKEN`, supply `LOCKTIVITY_CLIENT_ID` and
`LOCKTIVITY_CLIENT_SECRET`, set `pipeline_id`, and point the exchange at a
loopback auth endpoint:

```yaml
collectors:
  documents:
    binary: "/absolute/path/to/epack-collector-documents-dev"
    config:
      pipeline_id: "<pipeline id>"
      insecure_endpoint: "http://127.0.0.1:3000"
      insecure_auth_endpoint: "http://127.0.0.1:3001"
    secrets:
      - LOCKTIVITY_CLIENT_ID
      - LOCKTIVITY_CLIENT_SECRET
```

Custom auth endpoints follow the same dev-build loopback restriction. Plain
HTTP should only be used for local loopback testing because the token exchange
sends the client secret.

## Releasing

Tag the repo with a semantic version, such as `v0.1.0`. The release workflow
builds SLSA-attested binaries from the tag.

## License

Apache 2.0
