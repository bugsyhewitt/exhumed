package timefilter

import (
	"testing"
	"time"
)

func TestParse_Empty(t *testing.T) {
	for _, spec := range []string{"", "   ", "\t"} {
		f, err := Parse(spec)
		if err != nil {
			t.Fatalf("Parse(%q): unexpected error: %v", spec, err)
		}
		if f.Active() {
			t.Fatalf("Parse(%q): expected inactive filter", spec)
		}
		if f.Match(0) || f.Match(time.Second) {
			t.Fatalf("Parse(%q): inactive filter matched", spec)
		}
	}
}

func TestParse_GreaterThan(t *testing.T) {
	f, err := Parse(">500ms")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Active() {
		t.Fatal("expected active filter")
	}
	// Strictly greater: 500ms itself must NOT match.
	if f.Match(500 * time.Millisecond) {
		t.Error("Match(500ms) = true, want false (strict >)")
	}
	if !f.Match(501 * time.Millisecond) {
		t.Error("Match(501ms) = false, want true")
	}
	if f.Match(499 * time.Millisecond) {
		t.Error("Match(499ms) = true, want false")
	}
}

func TestParse_GreaterThanOrEqual(t *testing.T) {
	f, err := Parse(">=1s")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Match(time.Second) {
		t.Error("Match(1s) = false, want true (>=)")
	}
	if !f.Match(2 * time.Second) {
		t.Error("Match(2s) = false, want true")
	}
	if f.Match(999 * time.Millisecond) {
		t.Error("Match(999ms) = true, want false")
	}
}

func TestParse_LessThan(t *testing.T) {
	f, err := Parse("<100ms")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Match(99 * time.Millisecond) {
		t.Error("Match(99ms) = false, want true")
	}
	// Strictly less: 100ms itself must NOT match.
	if f.Match(100 * time.Millisecond) {
		t.Error("Match(100ms) = true, want false (strict <)")
	}
}

func TestParse_LessThanOrEqual(t *testing.T) {
	f, err := Parse("<=50ms")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Match(50 * time.Millisecond) {
		t.Error("Match(50ms) = false, want true (<=)")
	}
	if f.Match(51 * time.Millisecond) {
		t.Error("Match(51ms) = true, want false")
	}
}

func TestParse_MultipleTermsBandStop(t *testing.T) {
	// Suppress the very fast (<5ms) AND the very slow (>2s); keep the middle band.
	f, err := Parse(">2s, <5ms")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	suppressed := []time.Duration{
		1 * time.Millisecond, // too fast
		4 * time.Millisecond, // too fast
		3 * time.Second,      // too slow
		10 * time.Second,     // too slow
	}
	for _, d := range suppressed {
		if !f.Match(d) {
			t.Errorf("Match(%s) = false, want true (should be suppressed)", d)
		}
	}
	kept := []time.Duration{
		5 * time.Millisecond,   // boundary, strict < so kept
		500 * time.Millisecond, // middle band
		2 * time.Second,        // boundary, strict > so kept
	}
	for _, d := range kept {
		if f.Match(d) {
			t.Errorf("Match(%s) = true, want false (should be kept)", d)
		}
	}
}

func TestParse_WhitespaceAndTrailingComma(t *testing.T) {
	f, err := Parse("  >500ms , <10ms , ")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(f.bounds) != 2 {
		t.Fatalf("expected 2 bounds, got %d", len(f.bounds))
	}
	if !f.Match(time.Second) || !f.Match(5*time.Millisecond) {
		t.Error("expected both bounds active")
	}
}

func TestParse_Errors(t *testing.T) {
	for _, spec := range []string{
		"500ms", // no comparator
		">notaduration",
		">",     // comparator with no duration
		">-5ms", // negative
		"=>5ms", // bad comparator order
		"100",   // bare number, no comparator
	} {
		if _, err := Parse(spec); err == nil {
			t.Errorf("Parse(%q): expected error, got nil", spec)
		}
	}
}

func TestMatch_NegativeDuration(t *testing.T) {
	f, err := Parse(">0s")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if f.Match(-1 * time.Second) {
		t.Error("Match(negative) = true, want false")
	}
}

func TestMatch_NilFilter(t *testing.T) {
	var f *Filter
	if f.Active() {
		t.Error("nil filter Active() = true, want false")
	}
	if f.Match(time.Second) {
		t.Error("nil filter Match() = true, want false")
	}
}
