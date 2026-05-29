package matchwords

import "testing"

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
		if !f.Keep(0) || !f.Keep(27) || !f.Keep(9999) {
			t.Fatalf("Parse(%q): inactive filter should keep everything", spec)
		}
	}
}

func TestParse_ExactCounts(t *testing.T) {
	f, err := Parse("0,42")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Active() {
		t.Fatal("expected active filter")
	}
	for _, n := range []int{0, 42} {
		if !f.Keep(n) {
			t.Errorf("Keep(%d) = false, want true", n)
		}
	}
	// Everything not in the allowlist is dropped — the inverse of wordfilter.
	for _, n := range []int{1, 27, 41, 43, 9999} {
		if f.Keep(n) {
			t.Errorf("Keep(%d) = true, want false", n)
		}
	}
}

func TestParse_Range(t *testing.T) {
	// A common LFI recon gate: keep only bodies in the word-count band where
	// leaked file content lands, dropping the uniform soft-404 noise.
	f, err := Parse("10-20")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, n := range []int{10, 15, 20} {
		if !f.Keep(n) {
			t.Errorf("Keep(%d) in range = false, want true", n)
		}
	}
	for _, n := range []int{0, 9, 21, 9999} {
		if f.Keep(n) {
			t.Errorf("Keep(%d) outside range = true, want false", n)
		}
	}
}

func TestParse_MixedTermsAndWhitespace(t *testing.T) {
	f, err := Parse(" 0 , 10-20 , 42 ,")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cases := map[int]bool{
		0:    true,
		5:    false,
		10:   true,
		20:   true,
		21:   false,
		42:   true,
		9999: false,
	}
	for n, want := range cases {
		if got := f.Keep(n); got != want {
			t.Errorf("Keep(%d) = %v, want %v", n, got, want)
		}
	}
}

func TestParse_SingleValueRange(t *testing.T) {
	// "42-42" is a degenerate but legal range keeping exactly 42.
	f, err := Parse("42-42")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Keep(42) {
		t.Error("Keep(42) = false, want true")
	}
	if f.Keep(41) || f.Keep(43) {
		t.Error("single-value range kept a neighbour")
	}
}

func TestParse_ZeroIsValid(t *testing.T) {
	// Zero-word bodies are a legitimate, common LFI signal (empty include
	// output). They must be a valid allowlist target, not rejected as a floor
	// violation the way a status code below 100 would be.
	f, err := Parse("0")
	if err != nil {
		t.Fatalf("Parse(0): %v", err)
	}
	if !f.Keep(0) {
		t.Error("Keep(0) = false, want true")
	}
	if f.Keep(1) {
		t.Error("Keep(1) = true, want false")
	}
}

func TestParse_Errors(t *testing.T) {
	cases := []string{
		"abc",     // non-numeric
		"-5",      // negative (parsed as reversed/empty-low range)
		"20-10",   // reversed range
		"10-",     // missing high bound
		"-",       // empty range
		"10-abc",  // non-numeric high bound
		"5.0",     // float
		"10,oops", // one good, one bad
	}
	for _, spec := range cases {
		if _, err := Parse(spec); err == nil {
			t.Errorf("Parse(%q): expected error, got nil", spec)
		}
	}
}

func TestKeep_Nil(t *testing.T) {
	var f *Filter
	if f.Active() {
		t.Error("nil filter should be inactive")
	}
	// A nil (inactive) filter keeps everything.
	if !f.Keep(0) || !f.Keep(9999) {
		t.Error("nil filter should keep everything")
	}
	// KeepBody on a nil filter also keeps everything.
	if !f.KeepBody([]byte("anything at all")) {
		t.Error("nil filter KeepBody should keep everything")
	}
}

func TestKeep_NegativeNeverKeptWhenActive(t *testing.T) {
	f, err := Parse("0-10000")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// A negative count is nonsensical input; an active filter must not keep it
	// even though the range nominally spans zero.
	if f.Keep(-1) {
		t.Error("Keep(-1) = true, want false for an active filter")
	}
}

func TestKeepBody(t *testing.T) {
	// KeepBody must count words with the same definition the filter compares
	// against (strings.Fields semantics via wordfilter.CountWords).
	f, err := Parse("3")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	keep := [][]byte{
		[]byte("one two three"),
		[]byte("  one\ttwo\nthree  "), // runs of whitespace collapse
	}
	for _, b := range keep {
		if !f.KeepBody(b) {
			t.Errorf("KeepBody(%q) = false, want true (3 words)", b)
		}
	}
	drop := [][]byte{
		[]byte(""),                // 0 words
		[]byte("one two"),         // 2 words
		[]byte("one two three x"), // 4 words
	}
	for _, b := range drop {
		if f.KeepBody(b) {
			t.Errorf("KeepBody(%q) = true, want false", b)
		}
	}
}

func TestKeepBody_ZeroWords(t *testing.T) {
	// The empty / all-whitespace body has a word count of zero and must match a
	// "0" allowlist.
	f, err := Parse("0")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, b := range [][]byte{nil, []byte(""), []byte("   \t\n ")} {
		if !f.KeepBody(b) {
			t.Errorf("KeepBody(%q) = false, want true (0 words)", b)
		}
	}
	if f.KeepBody([]byte("word")) {
		t.Error("KeepBody(\"word\") = true, want false")
	}
}
