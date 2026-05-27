package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bugsyhewitt/exhumed/internal/feed"
)

// writeVersionMarker installs a feed version marker in dir, mirroring what
// feed.Update writes after a successful download.
func writeVersionMarker(t *testing.T, dir, version string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	path := filepath.Join(dir, feed.VersionMarkerFile)
	if err := os.WriteFile(path, []byte(version), 0o644); err != nil {
		t.Fatalf("write marker %s: %v", path, err)
	}
}

// withBundledDB swaps defaultDBPath behaviour by chdir-ing into a temp working
// directory that contains a "database" subdir, optionally carrying its own
// version marker. It returns the absolute path of that bundled dir and restores
// the original working directory on cleanup.
func withBundledDB(t *testing.T, bundledVersion string) string {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := t.TempDir()
	bundled := filepath.Join(root, defaultDBPath)
	if err := os.MkdirAll(bundled, 0o755); err != nil {
		t.Fatalf("mkdir bundled: %v", err)
	}
	if bundledVersion != "" {
		writeVersionMarker(t, bundled, bundledVersion)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir %s: %v", root, err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
	return bundled
}

func TestResolveDBPath(t *testing.T) {
	tests := []struct {
		name           string
		explicit       string
		bundledVersion string // "" → no marker on the bundled dir
		cacheVersion   string // "" → no cache marker installed
		wantSource     string
		wantCache      bool // true → expect the cache path; false → expect defaultDBPath
	}{
		{
			name:         "newer cache wins over bundled",
			explicit:     defaultDBPath,
			cacheVersion: "2026-05-20",
			wantSource:   dbSourceCache,
			wantCache:    true,
		},
		{
			name:           "older cache loses to bundled",
			explicit:       defaultDBPath,
			bundledVersion: "2026-05-20",
			cacheVersion:   "2026-05-10",
			wantSource:     dbSourceBundled,
			wantCache:      false,
		},
		{
			name:           "equal versions keep bundled",
			explicit:       defaultDBPath,
			bundledVersion: "2026-05-17",
			cacheVersion:   "2026-05-17",
			wantSource:     dbSourceBundled,
			wantCache:      false,
		},
		{
			name:         "missing cache falls back to bundled",
			explicit:     defaultDBPath,
			cacheVersion: "",
			wantSource:   dbSourceBundled,
			wantCache:    false,
		},
		{
			name:         "explicit db always wins",
			explicit:     "/some/custom/path",
			cacheVersion: "2099-01-01", // even a newer cache must be ignored
			wantSource:   dbSourceExplicit,
			wantCache:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundled := withBundledDB(t, tc.bundledVersion)
			cacheDir := t.TempDir()
			if tc.cacheVersion != "" {
				writeVersionMarker(t, cacheDir, tc.cacheVersion)
			}

			path, source := ResolveDBPath(tc.explicit, cacheDir)

			if source != tc.wantSource {
				t.Errorf("source = %q, want %q", source, tc.wantSource)
			}

			switch {
			case tc.wantSource == dbSourceExplicit:
				if path != tc.explicit {
					t.Errorf("explicit path = %q, want %q", path, tc.explicit)
				}
			case tc.wantCache:
				if path != cacheDir {
					t.Errorf("path = %q, want cache dir %q", path, cacheDir)
				}
			default:
				if path != defaultDBPath {
					t.Errorf("path = %q, want bundled %q", path, defaultDBPath)
				}
				// Sanity: the bundled dir we created actually exists at the
				// resolved relative path under the temp working directory.
				if _, err := os.Stat(bundled); err != nil {
					t.Errorf("bundled dir missing: %v", err)
				}
			}
		})
	}
}

// TestResolveDBPath_ExplicitDisablesResolver guards the invariant that an
// explicit --db is returned verbatim without touching the cache at all.
func TestResolveDBPath_ExplicitDisablesResolver(t *testing.T) {
	const explicit = "database/_raw"
	cacheDir := t.TempDir()
	writeVersionMarker(t, cacheDir, "2099-12-31")

	path, source := ResolveDBPath(explicit, cacheDir)
	if path != explicit {
		t.Errorf("path = %q, want %q", path, explicit)
	}
	if source != dbSourceExplicit {
		t.Errorf("source = %q, want %q", source, dbSourceExplicit)
	}
}
