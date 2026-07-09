#!/usr/bin/env bash
#
# Fails if the collector assembly layer starts emitting ephemeral snapshot
# fetch URLs or auth material. Document file bytes are evidence; pre-signed
# fetch URLs, bearer tokens, and client secrets are not.
#
# Suppress a deliberate, audited download-only use with a trailing
# "// LINT-ALLOW: <reason>".
set -euo pipefail

cd "$(dirname "$0")/.."

violations=$(
  find internal/collector -name '*.go' ! -name '*_test.go' -print0 \
    | xargs -0 grep -n -E 'FileURL|SourceURL|TextURL|file_url|source_url|text_url|Authorization|Bearer|client_secret|LOCKTIVITY_DOCUMENTS_TOKEN|LOCKTIVITY_CLIENT_SECRET' \
    | grep -v 'LINT-ALLOW:' \
    || true
)

if [ -n "$violations" ]; then
  echo "FORBIDDEN DOCUMENT SNAPSHOT DATA EMISSION DETECTED:"
  echo "$violations"
  echo
  echo "Fetch URLs and auth material may be used to retrieve evidence, but must not enter emitted artifacts."
  echo "If a use is download-only and reviewed, append '// LINT-ALLOW: <reason>' to that line."
  exit 1
fi

echo "forbidden-data check: clean"
