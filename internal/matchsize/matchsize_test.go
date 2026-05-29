package matchsize

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

func TestParse_ExactSizes(t *testing.T) {
	f, err := Parse("0,413")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Active() {
		t.Fatal("expected active filter")
	}
	for _, n := range []int{0, 413} {
		if !f.Keep(n) {
			t.Errorf("Keep(%d) = false, want true", n)
		}
	}
	// Everything not in the allowlist is dropped — the inverse of respfilter.
	for _, n := range []int{1, 27, 412, 414, 9999} {
		if f.Keep(n) {
			t.Errorf("Keep(%d) = true, want false", n)
		}
	}
}

func TestParse_Range(t *testing.T) {
	// A common LFI recon gate: keep only bodies in the size band where leaked
	// file content lands, dropping the uniform soft-404 noise.
	f, err := Parse("100-200")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, n := range []int{100, 150, 200} {
		if !f.Keep(n) {
			t.Errorf("Keep(%d) in range = false, want true", n)
		}
	}
	for _, n := range []int{0, 99, 201, 9999} {
		if f.Keep(n) {
			t.Errorf("Keep(%d) outside range = true, want false", n)
		}
	}
}

func TestParse_MixedTermsAndWhitespace(t *testing.T) {
	f, err := Parse(" 0 , 100-200 , 413 ,")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cases := map[int]bool{
		0:    true,
		50:   false,
		100:  true,
		200:  true,
		201:  false,
		413:  true,
		9999: false,
	}
	for n, want := range cases {
		if got := f.Keep(n); got != want {
			t.Errorf("Keep(%d) = %v, want %v", n, got, want)
		}
	}
}

func TestParse_SingleValueRange(t *testing.T) {
	// "413-413" is a degenerate but legal range keeping exactly 413.
	f, err := Parse("413-413")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Keep(413) {
		t.Error("Keep(413) = false, want true")
	}
	if f.Keep(412) || f.Keep(414) {
		t.Error("single-value range kept a neighbour")
	}
}

func TestParse_ZeroIsValid(t *testing.T) {
	// Zero-length bodies are a legitimate, common LFI signal (empty include
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
		"abc",      // non-numeric
		"-5",       // negative (parsed as reversed/empty-low range)
		"200-100",  // reversed range
		"100-",     // missing high bound
		"-",        // empty range
		"100-abc",  // non-numeric high bound
		"50.0",     // float
		"100,oops", // one good, one bad
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
}

func TestKeep_NegativeNeverKeptWhenActive(t *testing.T) {
	f, err := Parse("0-10000")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// A negative length is nonsensical input; an active filter must not keep it
	// even though the range nominally spans zero.
	if f.Keep(-1) {
		t.Error("Keep(-1) = true, want false for an active filter")
	}
}
