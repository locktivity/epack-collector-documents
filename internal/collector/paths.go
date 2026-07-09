package collector

import "path"

const (
	// DocumentIndexPackPath is the pack path for the top-level document index.
	DocumentIndexPackPath = "artifacts/documents.json"

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
