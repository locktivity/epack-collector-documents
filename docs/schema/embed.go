// Package schema embeds the JSON Schemas of the collector's artifacts and
// its trace map.
package schema

import _ "embed"

//go:embed document-index.v1.0.0.json
var documentIndex []byte

// TraceMap is the map in trace-map.json, which links each field of the
// index to the calls and the code behind it, for
// componentsdk.CollectorSpec.TraceMap. `make trace-map` rewrites it.
//
//go:embed trace-map.json
var TraceMap []byte

// Schemas maps the index's schema ID to its JSON Schema, for
// componentsdk.CollectorSpec.Schemas. document-text.v1.0.0.json describes the
// staged text files. Staged files are not checked against a schema, so it is
// not embedded.
func Schemas() map[string][]byte {
	return map[string][]byte{"evidencepack/document-index@v1": documentIndex}
}
