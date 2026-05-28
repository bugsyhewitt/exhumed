package db

import (
	"os"
	"path/filepath"
	"testing"
)

// curatedRoot returns the path to the repository's curated database/ directory,
// resolved relative to this test file (internal/db → ../../database). If the
// directory is absent (e.g. the package is vendored without the data tree) the
// test is skipped rather than failed.
func curatedRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join("..", "..", "database")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("curated database root not found at %s: %v", root, err)
	}
	return root
}

// TestCuratedDatabase_GateMet enforces the POST_V01 Item 4 acceptance gate:
// the curated database loads cleanly, has zero validation problems, and holds
// at least 150 entries. Growing the moat is the product; this guards it from
// regressing below the target or shipping a malformed entry.
func TestCuratedDatabase_GateMet(t *testing.T) {
	root := curatedRoot(t)

	d, err := LoadCurated(root)
	if err != nil {
		t.Fatalf("LoadCurated(%q): %v", root, err)
	}

	if problems := Validate(d); len(problems) != 0 {
		for _, p := range problems {
			t.Errorf("validation problem: %s", p.Error())
		}
		t.Fatalf("curated database has %d validation problem(s); want 0", len(problems))
	}

	const minEntries = 150
	if got := len(d.AllEntries()); got < minEntries {
		t.Fatalf("curated entry count = %d; POST_V01 Item 4 requires >= %d", got, minEntries)
	}
}

// TestCuratedDatabase_ModernCategoriesPresent verifies the database growth lap
// added coverage for the modern technology domains POST_V01 Item 4 called out
// (framework, cloud, ci-cd, credential-store, version-control) rather than only
// padding the existing groups.
func TestCuratedDatabase_ModernCategoriesPresent(t *testing.T) {
	root := curatedRoot(t)

	d, err := LoadCurated(root)
	if err != nil {
		t.Fatalf("LoadCurated(%q): %v", root, err)
	}

	stats := d.Stats()
	wantCategories := []string{
		string(CategoryFramework),
		string(CategoryCloud),
		string(CategoryCICD),
		string(CategoryCredentialStore),
		string(CategoryVersionControl),
		string(CategoryLanguageRuntime),
	}
	for _, cat := range wantCategories {
		if stats.PerCategory[cat] == 0 {
			t.Errorf("category %q has no curated entries; expected coverage after the growth lap", cat)
		}
	}
}

// TestCuratedDatabase_NoWeakConfirmPlaceholders guards against the `regex: .`
// weak-confirm placeholder leaking into the newly curated groups. The growth
// lap explicitly required real, discriminating confirm patterns (POST_V01
// Item 4), so the r2-curated provenance tag and a bare "." confirm pattern must
// never co-occur on the same entry.
func TestCuratedDatabase_NoWeakConfirmPlaceholders(t *testing.T) {
	root := curatedRoot(t)

	d, err := LoadCurated(root)
	if err != nil {
		t.Fatalf("LoadCurated(%q): %v", root, err)
	}

	for _, ce := range d.AllEntries() {
		isR2 := false
		for _, tag := range ce.Tags {
			if tag == "r2-curated" {
				isR2 = true
				break
			}
		}
		if !isR2 {
			continue
		}
		for _, pat := range ce.Confirm.Patterns {
			if pat == "." || pat == ".*" || pat == "" {
				t.Errorf("entry %q (%s) uses weak-confirm placeholder %q", ce.ID, ce.SourceFile, pat)
			}
		}
	}
}
