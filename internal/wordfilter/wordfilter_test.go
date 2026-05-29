package wordfilter

import "testing"

func TestParse_EmptySpecIsInactive(t *testing.T) {
	for _, spec := range []string{"", "   ", "\t"} {
		f, err := Parse(spec)
		if err != nil {
			t.Fatalf("Parse(%q) unexpected error: %v", spec, err)
		}
		if f.Active() {
			t.Fatalf("Parse(%q) should be inactive", spec)
		}
		if f.Match(5) {
			t.Fatalf("inactive filter must not match")
		}
	}
}

func TestParse_InvalidSpecs(t *testing.T) {
	for _, spec := range []string{
		"abc",     // non-numeric
		"-3",      // strconv reads this as a single negative integer term
		"10-x",    // bad range high
		"x-10",    // bad range low
		"20-10",   // reversed range
		"5,bad,7", // one bad term in a list
	} {
		if _, err := Parse(spec); err == nil {
			t.Fatalf("Parse(%q) expected error, got nil", spec)
		}
	}
}

func TestMatch_ExactAndRange(t *testing.T) {
	f, err := Parse("0,42,10-20")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Active() {
		t.Fatal("filter should be active")
	}

	cases := []struct {
		words int
		want  bool
	}{
		{0, true},   // exact 0
		{42, true},  // exact 42
		{10, true},  // range low edge
		{15, true},  // range middle
		{20, true},  // range high edge
		{9, false},  // just below range
		{21, false}, // just above range
		{41, false}, // adjacent to exact
		{43, false},
		{-1, false}, // negative guarded
	}
	for _, c := range cases {
		if got := f.Match(c.words); got != c.want {
			t.Errorf("Match(%d) = %v, want %v", c.words, got, c.want)
		}
	}
}

func TestParse_TrailingAndDoubledCommasTolerated(t *testing.T) {
	f, err := Parse(" 3 , , 7 ,")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Match(3) || !f.Match(7) {
		t.Fatal("expected 3 and 7 to match")
	}
	if f.Match(5) {
		t.Fatal("5 should not match")
	}
}

func TestCountWords(t *testing.T) {
	cases := []struct {
		body string
		want int
	}{
		{"", 0},
		{"   \t\n ", 0},
		{"one", 1},
		{"one two three", 3},
		{"  leading and   collapsed   spaces  ", 4},
		{"line1\nline2\tline3", 3},
	}
	for _, c := range cases {
		if got := CountWords([]byte(c.body)); got != c.want {
			t.Errorf("CountWords(%q) = %d, want %d", c.body, got, c.want)
		}
	}
}

// TestMatchBody verifies the convenience wrapper counts words then matches, and
// that the value-stability property holds: two bodies with the same word count
// but DIFFERENT byte lengths both match the same word-count filter — the gap
// that motivates this filter over --filter-size.
func TestMatchBody(t *testing.T) {
	f, err := Parse("4")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Both bodies have 4 words but different byte lengths (a varying token).
	short := []byte("not found id ab")
	long := []byte("not found id abcdef0123456789")
	if len(short) == len(long) {
		t.Fatal("test fixtures must differ in byte length")
	}
	if !f.MatchBody(short) {
		t.Errorf("MatchBody(short) should match (4 words)")
	}
	if !f.MatchBody(long) {
		t.Errorf("MatchBody(long) should match (4 words)")
	}

	// An inactive filter never matches.
	inactive, _ := Parse("")
	if inactive.MatchBody(short) {
		t.Errorf("inactive filter must not match any body")
	}
}
