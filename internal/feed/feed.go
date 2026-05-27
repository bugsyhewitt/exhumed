// Package feed implements the versioned database update system.
// It fetches a manifest from a remote feed, verifies SHA-256 checksums,
// and atomically swaps new files into a local cache directory.
package feed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// VersionMarkerFile is the filename in the cache dir that records the installed
// database version.
const VersionMarkerFile = ".db-version"

// Manifest describes a database release: schema version, DB version string
// (semver or date-based), and a list of files with their expected SHA-256 sums.
type Manifest struct {
	// SchemaVersion is the db schema_version used by the files in this release.
	// An installed binary that only understands schema 1 will refuse a manifest
	// declaring schema 2, preventing silent breakage.
	SchemaVersion int `json:"schema_version"`
	// DBVersion is the release version of this database (e.g. "2026-05-17" or "1.2.0").
	DBVersion string `json:"db_version"`
	// Files lists every downloadable file with its URL path (relative to the
	// manifest base URL) and expected SHA-256 checksum.
	Files []FileEntry `json:"files"`
}

// FileEntry is one file in the feed manifest.
type FileEntry struct {
	// Name is the filename (used as both the remote path and the local filename).
	Name string `json:"name"`
	// SHA256 is the expected lowercase hex SHA-256 of the file contents.
	SHA256 string `json:"sha256"`
}

// Config holds the parameters for a feed operation.
type Config struct {
	// FeedURL is the URL of the manifest.json (can be http://, https://, or file://).
	FeedURL string
	// CacheDir is the local directory where DB files are stored after download.
	CacheDir string
	// SupportedSchema is the highest db schema_version this binary understands.
	SupportedSchema int
}

// CheckResult is the result of a Check operation.
type CheckResult struct {
	UpdateAvailable bool
	LocalVersion    string
	RemoteVersion   string
}

// Check fetches the remote manifest and reports whether an update is available,
// without downloading or modifying any local files.
func Check(cfg Config) (CheckResult, error) {
	manifest, err := fetchManifest(cfg.FeedURL)
	if err != nil {
		return CheckResult{}, fmt.Errorf("fetch manifest: %w", err)
	}

	local := readVersion(cfg.CacheDir)
	result := CheckResult{
		LocalVersion:  local,
		RemoteVersion: manifest.DBVersion,
	}
	if newer(manifest.DBVersion, local) {
		result.UpdateAvailable = true
	}
	return result, nil
}

// Update fetches the remote manifest, compares versions, and — if the remote
// is newer — downloads all files, verifies checksums, and atomically swaps
// them into the cache dir. Returns true if any files were updated.
//
// If any checksum fails, the entire update is aborted and the existing DB
// files are left untouched.
func Update(cfg Config) (bool, error) {
	manifest, err := fetchManifest(cfg.FeedURL)
	if err != nil {
		return false, fmt.Errorf("fetch manifest: %w", err)
	}

	if manifest.SchemaVersion > cfg.SupportedSchema {
		return false, fmt.Errorf("feed schema_version %d is unsupported by this binary (supports <= %d): upgrade exhumed to use this database version",
			manifest.SchemaVersion, cfg.SupportedSchema)
	}

	local := readVersion(cfg.CacheDir)
	if !newer(manifest.DBVersion, local) {
		return false, nil // already up to date
	}

	baseURL := manifestBaseURL(cfg.FeedURL)

	// Download and verify all files to temp files BEFORE writing anything.
	type pending struct {
		name    string
		tmpPath string
	}
	var pendingFiles []pending

	cleanup := func() {
		for _, p := range pendingFiles {
			os.Remove(p.tmpPath)
		}
	}

	if err := os.MkdirAll(cfg.CacheDir, 0o755); err != nil {
		return false, fmt.Errorf("create cache dir: %w", err)
	}

	for _, fe := range manifest.Files {
		fileURL := baseURL + "/" + fe.Name
		data, err := fetchBytes(fileURL)
		if err != nil {
			cleanup()
			return false, fmt.Errorf("download %s: %w", fe.Name, err)
		}

		// Verify checksum before writing anything.
		got := sha256hex(data)
		if !strings.EqualFold(got, fe.SHA256) {
			cleanup()
			return false, fmt.Errorf("checksum verification failed for %s: got %s, want %s", fe.Name, got, fe.SHA256)
		}

		// Write to a temp file in the same directory (same filesystem → atomic rename).
		tmp, err := os.CreateTemp(cfg.CacheDir, ".tmp-"+fe.Name+"-*")
		if err != nil {
			cleanup()
			return false, fmt.Errorf("create temp file: %w", err)
		}
		if _, err := tmp.Write(data); err != nil {
			tmp.Close()
			cleanup()
			return false, fmt.Errorf("write temp %s: %w", fe.Name, err)
		}
		if err := tmp.Close(); err != nil {
			cleanup()
			return false, fmt.Errorf("close temp %s: %w", fe.Name, err)
		}

		pendingFiles = append(pendingFiles, pending{name: fe.Name, tmpPath: tmp.Name()})
	}

	// All files downloaded and verified. Atomically rename each temp → final.
	for _, p := range pendingFiles {
		dest := filepath.Join(cfg.CacheDir, p.name)
		if err := os.Rename(p.tmpPath, dest); err != nil {
			// Rename failed — leave remaining tmps for cleanup but don't touch existing.
			cleanup()
			return false, fmt.Errorf("atomic rename %s: %w", p.name, err)
		}
	}

	// Update the version marker.
	versionPath := filepath.Join(cfg.CacheDir, VersionMarkerFile)
	if err := os.WriteFile(versionPath, []byte(manifest.DBVersion), 0o644); err != nil {
		return true, fmt.Errorf("write version marker: %w", err)
	}

	return true, nil
}

// fetchManifest downloads and parses the manifest at the given URL.
func fetchManifest(feedURL string) (*Manifest, error) {
	data, err := fetchBytes(feedURL)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest JSON: %w", err)
	}
	return &m, nil
}

// fetchBytes retrieves the content at rawURL, supporting http://, https://, and file://.
func fetchBytes(rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}

	if u.Scheme == "file" {
		return os.ReadFile(u.Path)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", rawURL, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body from %s: %w", rawURL, err)
	}
	return data, nil
}

// manifestBaseURL returns the directory URL of the manifest, used to construct
// file download URLs.
func manifestBaseURL(manifestURL string) string {
	i := strings.LastIndex(manifestURL, "/")
	if i < 0 {
		return manifestURL
	}
	return manifestURL[:i]
}

// readVersion reads the installed DB version from the cache dir's version marker.
// Returns empty string if no version is installed yet.
func readVersion(cacheDir string) string {
	data, err := os.ReadFile(filepath.Join(cacheDir, VersionMarkerFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// LocalVersion reports the installed DB version recorded in dir's version marker
// (see VersionMarkerFile). It returns the empty string when dir contains no
// marker — i.e. no feed-managed database has been installed there. It performs
// no network access and never mutates state.
func LocalVersion(dir string) string {
	return readVersion(dir)
}

// IsNewer reports whether DB version a is newer than DB version b. Both are
// either semver strings or date strings (YYYY-MM-DD) and are compared with the
// same rule the feed uses to decide whether an update should be applied. An
// empty b ("not installed") makes any non-empty a newer.
func IsNewer(a, b string) bool {
	return newer(a, b)
}

// newer reports whether remote is a newer version than local.
// Both are either semver strings or date strings (YYYY-MM-DD).
// Empty local means "not installed" → remote is always newer.
func newer(remote, local string) bool {
	if local == "" {
		return true
	}
	// Simple lexicographic comparison works for both YYYY-MM-DD and semver
	// with consistent formatting.
	return remote > local
}

func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
