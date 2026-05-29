package linefilter

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
		lines int
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
		if got := f.Match(c.lines); got != c.want {
			t.Errorf("Match(%d) = %v, want %v", c.lines, got, c.want)
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

// TestCountLines verifies the ffuf-compatible line-count definition: the number
// of '\n' terminators. A trailing-newline-less body's final fragment is not a
// line, and CRLF counts as one line.
func TestCountLines(t *testing.T) {
	cases := []struct {
		body string
		want int
	}{
		{"", 0},                      // empty body
		{"no newline here", 0},       // no terminator
		{"a\n", 1},                   // one terminated line
		{"a\nb\n", 2},                // two terminated lines
		{"a\nb", 1},                  // trailing "b" not terminated
		{"a\r\nb\r\n", 2},            // CRLF: only '\n' counted
		{"\n\n\n", 3},                // three blank lines
		{"line1\nline2\nline3\n", 3}, // typical multi-line body
	}
	for _, c := range cases {
		if got := CountLines([]byte(c.body)); got != c.want {
			t.Errorf("CountLines(%q) = %d, want %d", c.body, got, c.want)
		}
	}
}

// TestMatchBody verifies the convenience wrapper counts lines then matches, and
// that the value-stability property holds: two bodies with the same line count
// but DIFFERENT byte lengths AND DIFFERENT word counts both match the same
// line-count filter — the gap that motivates this filter over --filter-size and
// --filter-words.
func TestMatchBody(t *testing.T) {
	f, err := Parse("2")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Both bodies have 2 lines but different byte lengths AND different word
	// counts (a varying multi-word fragment on line two).
	short := []byte("not found\nrequest GET /a\n")
	long := []byte("not found\nrequest GET /aaaa?x=1&y=2&z=3\n")
	if len(short) == len(long) {
		t.Fatal("test fixtures must differ in byte length")
	}
	if !f.MatchBody(short) {
		t.Errorf("MatchBody(short) should match (2 lines)")
	}
	if !f.MatchBody(long) {
		t.Errorf("MatchBody(long) should match (2 lines)")
	}

	// An inactive filter never matches.
	inactive, _ := Parse("")
	if inactive.MatchBody(short) {
		t.Errorf("inactive filter must not match any body")
	}
}
