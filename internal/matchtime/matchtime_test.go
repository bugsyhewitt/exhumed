package matchtime

import (
	"testing"
	"time"
)

func TestParse_Empty(t *testing.T) {
	for _, spec := range []string{"", "   ", "\t", "\n  "} {
		f, err := Parse(spec)
		if err != nil {
			t.Fatalf("Parse(%q): unexpected error: %v", spec, err)
		}
		if f.Active() {
			t.Fatalf("Parse(%q): expected inactive filter", spec)
		}
		// An inactive match filter keeps everything.
		if !f.Keep(0) || !f.Keep(time.Second) || !f.Keep(time.Hour) {
			t.Fatalf("Parse(%q): inactive filter should keep everything", spec)
		}
	}
}

func TestParse_GreaterThan(t *testing.T) {
	f, err := Parse(">50ms")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Active() {
		t.Fatal("expected active filter")
	}
	// Strictly greater: 50ms itself is NOT kept.
	if f.Keep(50 * time.Millisecond) {
		t.Error("Keep(50ms) = true, want false (strict >)")
	}
	if !f.Keep(51 * time.Millisecond) {
		t.Error("Keep(51ms) = false, want true")
	}
	if f.Keep(49 * time.Millisecond) {
		t.Error("Keep(49ms) = true, want false")
	}
}

func TestParse_GreaterThanOrEqual(t *testing.T) {
	f, err := Parse(">=1s")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Keep(time.Second) {
		t.Error("Keep(1s) = false, want true (>=)")
	}
	if !f.Keep(2 * time.Second) {
		t.Error("Keep(2s) = false, want true")
	}
	if f.Keep(999 * time.Millisecond) {
		t.Error("Keep(999ms) = true, want false")
	}
}

func TestParse_LessThan(t *testing.T) {
	f, err := Parse("<100ms")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Keep(99 * time.Millisecond) {
		t.Error("Keep(99ms) = false, want true")
	}
	// Strictly less: 100ms itself is NOT kept.
	if f.Keep(100 * time.Millisecond) {
		t.Error("Keep(100ms) = true, want false (strict <)")
	}
}

func TestParse_LessThanOrEqual(t *testing.T) {
	f, err := Parse("<=50ms")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Keep(50 * time.Millisecond) {
		t.Error("Keep(50ms) = false, want true (<=)")
	}
	if f.Keep(51 * time.Millisecond) {
		t.Error("Keep(51ms) = true, want false")
	}
}

func TestParse_MultipleTermsUnionEdges(t *testing.T) {
	// Keep the very fast (<5ms) OR the very slow (>2s); drop the middle band.
	// matchtime is the inverse of timefilter's band-stop: any bound satisfied
	// keeps the response.
	f, err := Parse(">2s, <5ms")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	kept := []time.Duration{
		1 * time.Millisecond, // very fast
		4 * time.Millisecond, // very fast
		3 * time.Second,      // very slow
		10 * time.Second,     // very slow
	}
	for _, d := range kept {
		if !f.Keep(d) {
			t.Errorf("Keep(%s) = false, want true (should be kept)", d)
		}
	}
	dropped := []time.Duration{
		5 * time.Millisecond,   // boundary, strict < so dropped
		500 * time.Millisecond, // middle band
		2 * time.Second,        // boundary, strict > so dropped
	}
	for _, d := range dropped {
		if f.Keep(d) {
			t.Errorf("Keep(%s) = true, want false (should be dropped)", d)
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
	if !f.Keep(time.Second) || !f.Keep(5*time.Millisecond) {
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

func TestKeep_NegativeDuration(t *testing.T) {
	f, err := Parse(">0s")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// A negative duration is nonsensical input; an active filter must not keep it.
	if f.Keep(-1 * time.Second) {
		t.Error("Keep(negative) = true, want false")
	}
}

func TestKeep_NilFilter(t *testing.T) {
	var f *Filter
	if f.Active() {
		t.Error("nil filter Active() = true, want false")
	}
	// A nil (inactive) filter keeps everything.
	if !f.Keep(time.Second) || !f.Keep(0) {
		t.Error("nil filter should keep everything")
	}
}
