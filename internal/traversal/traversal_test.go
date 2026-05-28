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
		"waf-double-slash",
		"waf-overlong-slash",
		"waf-encoded-backslash",
		"waf-dotslash-prefix",
		"waf-null-interstitial",
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
		"waf-double-slash":         true,
		"waf-overlong-slash":       true,
		"waf-encoded-backslash":    true,
		"waf-dotslash-prefix":      true,
		"waf-null-interstitial":    true,
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

func TestGenerate_WAFEvasionValues(t *testing.T) {
	payloads := Generate("etc/passwd", 1)

	want := map[string]string{
		"waf-double-slash":      "..%252fetc/passwd",
		"waf-overlong-slash":    "..%c0%afetc/passwd",
		"waf-encoded-backslash": "..%5cetc/passwd",
		"waf-dotslash-prefix":   "./../etc/passwd",
		"waf-null-interstitial": "..%00/etc/passwd",
	}

	got := map[string]string{}
	for _, p := range payloads {
		if _, ok := want[p.Technique]; ok {
			got[p.Technique] = p.Value
		}
	}

	for tech, exp := range want {
		if got[tech] != exp {
			t.Errorf("%s depth=1: got %q, want %q", tech, got[tech], exp)
		}
	}
}

func TestGenerate_WAFEvasionDepth(t *testing.T) {
	depth := 3
	payloads := Generate("etc/passwd", depth)

	counts := map[string]int{}
	wafTechs := []string{
		"waf-double-slash", "waf-overlong-slash", "waf-encoded-backslash",
		"waf-dotslash-prefix", "waf-null-interstitial",
	}
	wafSet := map[string]bool{}
	for _, t := range wafTechs {
		wafSet[t] = true
	}
	for _, p := range payloads {
		if wafSet[p.Technique] {
			counts[p.Technique]++
		}
	}
	for _, tech := range wafTechs {
		if counts[tech] != depth {
			t.Errorf("%s: expected %d payloads at depth=%d, got %d", tech, depth, depth, counts[tech])
		}
	}
}

func TestTechniques_MatchesGenerateOutput(t *testing.T) {
	payloads := Generate("etc/passwd", 4)

	emitted := map[string]bool{}
	for _, p := range payloads {
		emitted[p.Technique] = true
	}

	declared := Techniques()
	declaredSet := map[string]bool{}
	for _, t := range declared {
		declaredSet[t] = true
	}

	// Every emitted technique must be declared.
	for tech := range emitted {
		if !declaredSet[tech] {
			t.Errorf("Generate emits technique %q not declared in Techniques()", tech)
		}
	}
	// Every declared technique must actually be emitted.
	for _, tech := range declared {
		if !emitted[tech] {
			t.Errorf("Techniques() declares %q but Generate never emits it", tech)
		}
	}
}

func TestTechniques_OrderMatchesFirstAppearance(t *testing.T) {
	payloads := Generate("etc/passwd", 4)

	// Build first-appearance order from Generate output.
	var order []string
	seen := map[string]bool{}
	for _, p := range payloads {
		if !seen[p.Technique] {
			seen[p.Technique] = true
			order = append(order, p.Technique)
		}
	}

	declared := Techniques()
	if len(order) != len(declared) {
		t.Fatalf("technique count mismatch: Generate first-appearance=%d, Techniques()=%d", len(order), len(declared))
	}
	for i := range order {
		if order[i] != declared[i] {
			t.Errorf("order mismatch at %d: Generate=%q, Techniques()=%q", i, order[i], declared[i])
		}
	}
}

func TestGenerateFiltered_Subset(t *testing.T) {
	include := []string{"dotdot-slash", "php-filter"}
	payloads := GenerateFiltered("etc/passwd", 4, include)

	if len(payloads) == 0 {
		t.Fatal("expected payloads, got none")
	}
	allowed := map[string]bool{"dotdot-slash": true, "php-filter": true}
	sawSlash, sawPHP := false, false
	for _, p := range payloads {
		if !allowed[p.Technique] {
			t.Errorf("unexpected technique %q in filtered output", p.Technique)
		}
		if p.Technique == "dotdot-slash" {
			sawSlash = true
		}
		if p.Technique == "php-filter" {
			sawPHP = true
		}
	}
	if !sawSlash || !sawPHP {
		t.Errorf("filtered output missing requested techniques: slash=%v php=%v", sawSlash, sawPHP)
	}
}

func TestGenerateFiltered_EmptyIncludeMeansAll(t *testing.T) {
	all := Generate("etc/passwd", 4)
	filteredNil := GenerateFiltered("etc/passwd", 4, nil)
	filteredEmpty := GenerateFiltered("etc/passwd", 4, []string{})

	if len(filteredNil) != len(all) {
		t.Errorf("nil include: got %d payloads, want %d (all)", len(filteredNil), len(all))
	}
	if len(filteredEmpty) != len(all) {
		t.Errorf("empty include: got %d payloads, want %d (all)", len(filteredEmpty), len(all))
	}
}

func TestGenerateFiltered_PreservesOrdering(t *testing.T) {
	// Plain dotdot-slash should still precede url-encoded when both selected.
	payloads := GenerateFiltered("etc/passwd", 4, []string{"url-encoded", "dotdot-slash"})

	plainIdx, encodedIdx := -1, -1
	for i, p := range payloads {
		if p.Technique == "dotdot-slash" && plainIdx == -1 {
			plainIdx = i
		}
		if p.Technique == "url-encoded" && encodedIdx == -1 {
			encodedIdx = i
		}
	}
	if plainIdx == -1 || encodedIdx == -1 {
		t.Fatalf("missing techniques: plain=%d encoded=%d", plainIdx, encodedIdx)
	}
	if plainIdx >= encodedIdx {
		t.Errorf("ordering not preserved: plain idx %d should precede encoded idx %d", plainIdx, encodedIdx)
	}
}

func TestGenerateFiltered_UnknownIgnored(t *testing.T) {
	payloads := GenerateFiltered("etc/passwd", 4, []string{"dotdot-slash", "does-not-exist"})
	for _, p := range payloads {
		if p.Technique != "dotdot-slash" {
			t.Errorf("unexpected technique %q (unknown name should be ignored)", p.Technique)
		}
	}
	if len(payloads) == 0 {
		t.Error("expected dotdot-slash payloads, got none")
	}
}
