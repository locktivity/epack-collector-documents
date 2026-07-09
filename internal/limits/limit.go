// Package limits centralizes security-sensitive bounds.
package limits

import "time"

const (
	// CollectorTimeout is the total SDK runtime budget for this collector.
	CollectorTimeout = 10 * time.Minute

	// APIRequestTimeout bounds control-plane calls.
	APIRequestTimeout = 60 * time.Second

	// DownloadTimeout bounds a single document file or text download.
	DownloadTimeout = 5 * time.Minute

	// SnapshotCreateAttempts limits snapshot creation retries.
	SnapshotCreateAttempts = 3

	// SnapshotRetryBackoffStep is multiplied by the retry attempt.
	SnapshotRetryBackoffStep = 2 * time.Second

	// DownloadRedirects limits file download redirect hops.
	DownloadRedirects = 5

	// DownloadBytes matches epack's per-artifact limit.
	DownloadBytes int64 = 100 << 20

	// SnapshotResponseBytes bounds the snapshot manifest JSON response.
	SnapshotResponseBytes int64 = 32 << 20

	// TokenResponseBytes bounds the OAuth token response JSON body.
	TokenResponseBytes int64 = 1 << 20

	// ErrorResponseBytes bounds server error bodies copied into diagnostics.
	ErrorResponseBytes int64 = 4096

	// SHA256HexChars is the length of a SHA-256 digest in lowercase hex.
	SHA256HexChars = 64
)

// SnapshotRetryDelay returns the delay before a retry attempt.
func SnapshotRetryDelay(attempt int) time.Duration {
	return time.Duration(attempt-1) * SnapshotRetryBackoffStep
}
