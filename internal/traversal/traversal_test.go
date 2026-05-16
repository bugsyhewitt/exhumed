package traversal

import (
	"strings"
	"testing"
)

func TestGenerate_AllTechniquesPresent(t *testing.T) {
	payloads := Generate("etc/passwd", 4)

	want := []string{
		"dotdot-slash",
		"dotdot-backslash",
		"dotdotdotdot-doubleslash",
		"url-encoded",
		"url-encoded-dots",
		"url-encoded-slash",
		"double-url-encoded",
		"overlong-utf8",
		"unicode-fullwidth",
		"null-byte-percent",
		"null-byte-raw",
		"absolute-path",
		"php-filter",
		"file-uri",
	}

	got := map[string]bool{}
	for _, p := range payloads {
		got[p.Technique] = true
	}

	for _, tech := range want {
		if !got[tech] {
			t.Errorf("technique %q missing from output", tech)
		}
	}
}

func TestGenerate_Ordering_PlainBeforeEncoded(t *testing.T) {
	payloads := Generate("etc/passwd", 4)

	var plainIdx, encodedIdx int = -1, -1
	for i, p := range payloads {
		if p.Technique == "dotdot-slash" && plainIdx == -1 {
			plainIdx = i
		}
		if p.Technique == "url-encoded" && encodedIdx == -1 {
			encodedIdx = i
		}
	}

	if plainIdx == -1 {
		t.Fatal("dotdot-slash technique not found")
	}
	if encodedIdx == -1 {
		t.Fatal("url-encoded technique not found")
	}
	if plainIdx >= encodedIdx {
		t.Errorf("plain (idx %d) should appear before url-encoded (idx %d)", plainIdx, encodedIdx)
	}
}

func TestGenerate_Depth1_PlainPrefix(t *testing.T) {
	payloads := Generate("etc/passwd", 1)

	var plainCount int
	for _, p := range payloads {
		if p.Technique == "dotdot-slash" {
			plainCount++
			if p.Value != "../etc/passwd" {
				t.Errorf("depth=1 plain: got %q, want %q", p.Value, "../etc/passwd")
			}
		}
	}
	if plainCount != 1 {
		t.Errorf("depth=1 should produce exactly 1 dotdot-slash payload, got %d", plainCount)
	}
}

func TestGenerate_Depth2_PlainPrefix(t *testing.T) {
	payloads := Generate("etc/passwd", 2)

	found := false
	for _, p := range payloads {
		if p.Technique == "dotdot-slash" && p.Value == "../../etc/passwd" {
			found = true
			break
		}
	}
	if !found {
		t.Error("depth=2 plain: expected ../../etc/passwd not found")
	}
}

func TestGenerate_WrapperCategory(t *testing.T) {
	payloads := Generate("etc/passwd", 4)

	for _, p := range payloads {
		if p.Technique == "php-filter" || p.Technique == "file-uri" {
			if p.Category != "wrapper" {
				t.Errorf("technique %q should have Category=wrapper, got %q", p.Technique, p.Category)
			}
		}
	}
}

func TestGenerate_TraversalCategory(t *testing.T) {
	payloads := Generate("etc/passwd", 4)

	traversalTechs := map[string]bool{
		"dotdot-slash":             true,
		"dotdot-backslash":         true,
		"dotdotdotdot-doubleslash": true,
		"url-encoded":              true,
		"url-encoded-dots":         true,
		"url-encoded-slash":        true,
		"double-url-encoded":       true,
		"overlong-utf8":            true,
		"unicode-fullwidth":        true,
		"null-byte-percent":        true,
		"null-byte-raw":            true,
		"absolute-path":            true,
	}

	for _, p := range payloads {
		if traversalTechs[p.Technique] {
			if p.Category != "traversal" {
				t.Errorf("technique %q should have Category=traversal, got %q", p.Technique, p.Category)
			}
		}
	}
}

func TestGenerate_SanityCount(t *testing.T) {
	payloads := Generate("etc/passwd", 8)
	if len(payloads) < 50 {
		t.Errorf("expected >= 50 payloads for depth=8, got %d", len(payloads))
	}
}

func TestGenerate_StripsLeadingSlash(t *testing.T) {
	p1 := Generate("etc/passwd", 1)
	p2 := Generate("/etc/passwd", 1)

	// Both should produce identical values
	if len(p1) != len(p2) {
		t.Fatalf("length mismatch: %d vs %d", len(p1), len(p2))
	}
	for i := range p1 {
		if p1[i].Value != p2[i].Value {
			t.Errorf("index %d: %q != %q", i, p1[i].Value, p2[i].Value)
		}
	}
}

func TestGenerate_WrapperOrderedLast(t *testing.T) {
	payloads := Generate("etc/passwd", 4)

	// All wrappers must come after all traversal payloads
	lastTraversalIdx := -1
	firstWrapperIdx := -1
	for i, p := range payloads {
		if p.Category == "traversal" {
			lastTraversalIdx = i
		}
		if p.Category == "wrapper" && firstWrapperIdx == -1 {
			firstWrapperIdx = i
		}
	}

	if firstWrapperIdx == -1 {
		t.Fatal("no wrapper payloads found")
	}
	if lastTraversalIdx > firstWrapperIdx {
		t.Errorf("traversal payload at idx %d appears after first wrapper at idx %d",
			lastTraversalIdx, firstWrapperIdx)
	}
}

func TestGenerate_NullByteSuffix(t *testing.T) {
	payloads := Generate("etc/passwd", 2)

	for _, p := range payloads {
		if p.Technique == "null-byte-percent" {
			if !strings.HasSuffix(p.Value, "%00") {
				t.Errorf("null-byte-percent: expected %%00 suffix in %q", p.Value)
			}
		}
		if p.Technique == "null-byte-raw" {
			if !strings.HasSuffix(p.Value, "\x00") {
				t.Errorf("null-byte-raw: expected \\x00 suffix in %q", p.Value)
			}
		}
	}
}
