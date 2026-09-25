// Package buildinfo provides version, commit hash, and build date
// injected via ldflags at build time.
package buildinfo

var (
	// Version is the semantic version string (e.g., "v1.4.0").
	Version = "unknown"
	// Commit is the full git SHA of the built commit.
	Commit = "unknown"
	// ShortCommit is the abbreviated 7-char SHA.
	ShortCommit = "unknown"
	// Date is the UTC build timestamp in RFC3339 format.
	Date = "unknown"
)
