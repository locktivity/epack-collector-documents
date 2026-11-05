package collector

import (
	"path"

	"github.com/locktivity/epack/componentsdk"
)

// collectorName is the name in the collector's spec. Artifact paths in the
// code use it.
const collectorName = "documents"

// DocumentIndexPackPath is the pack path for the top-level document index.
var DocumentIndexPackPath = componentsdk.ArtifactPath(collectorName, DocumentIndexSchema)

const (
	artifactRoot         = "artifacts"
	documentRoot         = "documents"
	documentTextFile     = "text.json"
	documentMetadataFile = "metadata.json"
)

func documentDir(documentID string) string {
	return path.Join(documentRoot, documentID)
}

func documentArtifactRelPath(documentID, filename string) string {
	return path.Join(documentDir(documentID), filename)
}

func documentTextRelPath(documentID string) string {
	return documentArtifactRelPath(documentID, documentTextFile)
}

func documentMetadataRelPath(documentID string) string {
	return documentArtifactRelPath(documentID, documentMetadataFile)
}

func artifactPackPath(relPath string) string {
	return path.Join(artifactRoot, relPath)
}
