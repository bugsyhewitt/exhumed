// Package version exposes build-time metadata set via -ldflags.
package version

var (
	// Version is the semantic version string (e.g. "1.2.3").
	Version = "1.0.0"
	// Commit is the VCS commit hash at build time.
	Commit = "none"
	// Date is the build timestamp in RFC3339 format.
	Date = "unknown"
)
