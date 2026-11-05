package collector

import (
	"net/http"
	"slices"
	"testing"

	"github.com/locktivity/epack-collector-documents/internal/locktivity"
	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

// kitCleanExpect pins the document with no file yet: its entry stays in the
// index with no file.
var kitCleanExpect = map[string]map[string]any{DocumentIndexPackPath: {
	"/documents/3/name": "Incident response plan",
	"/documents/3/file": nil,
}}

// kitTamperedExpect pins the tampered scenario: the access control policy
// keeps its entry without its files, and the documents around it ship.
var kitTamperedExpect = map[string]map[string]any{DocumentIndexPackPath: {
	"/documents/0/file/path": "artifacts/documents/doc_1/acme-soc2-2025.pdf",
	"/documents/1/name":      "Access control policy",
	"/documents/1/file":      nil,
	"/documents/1/text":      nil,
	"/documents/2/file/path": "artifacts/documents/doc_3/vendor-inventory.xlsx",
}}

// kitSemantics declares the snapshot request's 404, which Locktivity sends
// for an account without the Documents feature or a pipeline outside the
// account. Either is the customer's to fix.
var kitSemantics = []collectortest.Semantic{{
	Operation:     locktivity.OpCreateSnapshot,
	Fault:         "404",
	Meaning:       "no Documents feature, or the pipeline is not in the account",
	ExpectFailure: componentsdk.CodeConfigInvalid,
}}

// The clean scenario signs in with client credentials: that sign-in calls
// every operation, and the fault matrix runs on the clean scenario alone.
// Scenarios with the token Locktivity brokers for managed pipelines override
// the credentials and send no pipeline_id.
func TestCollectorKit(t *testing.T) {
	signedIn := func(responses []collectortest.Response) []collectortest.Response {
		return append([]collectortest.Response{kitTokenResponse()}, responses...)
	}
	tokenError := func(status int, body string) []collectortest.Response {
		return []collectortest.Response{{Method: http.MethodPost, URL: kitTokenURL, Status: status, Body: body}}
	}
	brokeredSecrets := map[string]string{locktivity.EnvDocumentsToken: kitToken}
	brokeredConfig := map[string]any{configPipelineID: ""}

	collectortest.Run(t, collectortest.Suite{
		Spec:   kitSpec(),
		Run:    Run,
		Config: map[string]any{configRunKey: kitRunKey, configPipelineID: kitPipelineID},
		Secrets: map[string]string{
			locktivity.EnvClientID:     kitClientID,
			locktivity.EnvClientSecret: kitClientSecret,
		},
		Scenarios: []collectortest.Scenario{
			{Name: "clean", Responses: signedIn(kitResponses(kitLibrary())), Expect: kitCleanExpect},
			{
				Name:          "client rejected",
				ExpectFailure: componentsdk.CodeAuthFailed,
				Responses:     tokenError(http.StatusUnauthorized, `{"error":"invalid_client","error_description":"Client authentication failed due to unknown client."}`),
			},
			{
				Name:          "application without the client credentials grant",
				ExpectFailure: componentsdk.CodePermissionDenied,
				Responses:     tokenError(http.StatusBadRequest, `{"error":"unauthorized_client","error_description":"The client is not authorized to perform this request using this method."}`),
			},
			{
				Name:          "scope not granted",
				ExpectFailure: componentsdk.CodePermissionDenied,
				Responses:     tokenError(http.StatusBadRequest, `{"error":"invalid_scope","error_description":"The requested scope is invalid, unknown, or malformed."}`),
			},
			{
				Name:          "token endpoint unavailable",
				ExpectFailure: componentsdk.CodeVendorError,
				Responses:     tokenError(http.StatusServiceUnavailable, `<html>Service Unavailable</html>`),
			},
			{
				Name: "brokered token", Config: brokeredConfig, Secrets: brokeredSecrets,
				Responses: kitResponses(kitLibrary()), Expect: kitCleanExpect,
			},
			{
				Name: "brokered token rejected", Config: brokeredConfig, Secrets: brokeredSecrets,
				ExpectFailure: componentsdk.CodeAuthFailed,
				Responses: []collectortest.Response{{
					Method: http.MethodPost, URL: kitSnapshotURL, Status: http.StatusUnauthorized,
					Body: `{"errors":["Unauthorized"],"code":"UNAUTHORIZED"}`,
				}},
			},
			{
				Name:          "pipeline without the Documents collector",
				ExpectFailure: componentsdk.CodeConfigInvalid,
				Responses: signedIn([]collectortest.Response{{
					Method: http.MethodPost, URL: kitSnapshotURL, Status: http.StatusUnprocessableEntity,
					Body: `{"errors":["Pipeline has no documents collector"],"code":"VALIDATION_ERROR"}`,
				}}),
			},
			{Name: "empty library", Responses: signedIn(kitResponses(nil))},
			{Name: "a download fails its checksum", Responses: signedIn(kitTampered()), Expect: kitTamperedExpect},
		},
		Required:    []string{locktivity.OpCreateToken, locktivity.OpCreateSnapshot},
		Semantics:   kitSemantics,
		Operations:  kitOperations,
		Insensitive: []string{locktivity.OpCreateToken},
		// Each download is a file whose bytes must match the snapshot's
		// checksum, so the order of its lists is fixed.
		Ordered: []string{locktivity.FileDownload.Name, locktivity.SourceDownload.Name, locktivity.TextDownload.Name},
	})
}

// kitSpec is the collector's spec with the library's document types added to
// Writes. A metadata file's schema ID is its document's type in Locktivity,
// so the spec cannot list them ahead of time. The index and text schemas stay
// checked against the spec's own list.
func kitSpec() componentsdk.CollectorSpec {
	spec := Spec("test", "collectortest")
	for _, d := range kitLibrary() {
		if d.documentType != "" && !slices.Contains(spec.Writes, d.documentType) {
			spec.Writes = append(spec.Writes, d.documentType)
		}
	}
	return spec
}

// TestCollectorKitUnderAnotherName runs the clean scenario configured as
// policies. The index, the pointers in it and every file then sit under
// artifacts/policies, and the index still matches its schema.
func TestCollectorKitUnderAnotherName(t *testing.T) {
	collectortest.Run(t, collectortest.Suite{
		Name:   "policies",
		Spec:   kitSpec(),
		Run:    Run,
		Config: map[string]any{configRunKey: kitRunKey, configPipelineID: kitPipelineID},
		Secrets: map[string]string{
			locktivity.EnvClientID:     kitClientID,
			locktivity.EnvClientSecret: kitClientSecret,
		},
		Scenarios: []collectortest.Scenario{
			{Name: "clean", Responses: append([]collectortest.Response{kitTokenResponse()}, kitResponses(kitLibrary())...), Expect: map[string]map[string]any{DocumentIndexPackPath: {
				"/documents/0/file/path": "artifacts/policies/doc_1/acme-soc2-2025.pdf",
				"/documents/3/file":      nil,
			}}},
		},
		Required:    []string{locktivity.OpCreateToken, locktivity.OpCreateSnapshot},
		Semantics:   kitSemantics,
		Operations:  kitOperations,
		Insensitive: []string{locktivity.OpCreateToken},
		Ordered:     []string{locktivity.FileDownload.Name, locktivity.SourceDownload.Name, locktivity.TextDownload.Name},
	})
}
