// Pins the v1.0 release contract for exhumed:
//
//	(1) version.Version must equal "1.0.0" (was "dev" pre-release).
//	(2) CHANGELOG.md must contain a "## [1.0.0]" entry.
//
// If either regresses, the v1.0 flip is no longer valid — fail the build.
package version

import (
	"os"
	"regexp"
	"testing"
)

func TestVersion_IsV1_0_0(t *testing.T) {
	got := Version
	want := "1.0.0"
	if got != want {
		t.Errorf("Version = %q, want %q (v1.0 release contract)", got, want)
	}
}

func TestCHANGELOG_HasV1_0_0Entry(t *testing.T) {
	// internal/version/version_test.go -> ../../CHANGELOG.md -> repo root
	const rel = "../../CHANGELOG.md"
	data, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	re := regexp.MustCompile(`(?m)^## \[1\.0\.0\]`)
	if !re.MatchString(string(data)) {
		t.Errorf("CHANGELOG.md missing v1.0.0 entry header (pattern %q not found)", re.String())
	}
}
