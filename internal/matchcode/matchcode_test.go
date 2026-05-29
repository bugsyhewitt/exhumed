package matchcode

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
		if !f.Keep(200) || !f.Keep(404) || !f.Keep(500) {
			t.Fatalf("Parse(%q): inactive filter should keep everything", spec)
		}
	}
}

func TestParse_ExactCodes(t *testing.T) {
	f, err := Parse("200,500")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Active() {
		t.Fatal("expected active filter")
	}
	for _, c := range []int{200, 500} {
		if !f.Keep(c) {
			t.Errorf("Keep(%d) = false, want true", c)
		}
	}
	// Everything not in the allowlist is dropped — the inverse of codefilter.
	for _, c := range []int{301, 403, 404, 499, 501} {
		if f.Keep(c) {
			t.Errorf("Keep(%d) = true, want false", c)
		}
	}
}

func TestParse_Range(t *testing.T) {
	// A common LFI recon gate: keep only 5xx, where a crashing include() sink
	// surfaces.
	f, err := Parse("500-599")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, c := range []int{500, 502, 599} {
		if !f.Keep(c) {
			t.Errorf("Keep(%d) in range = false, want true", c)
		}
	}
	for _, c := range []int{200, 404, 499} {
		if f.Keep(c) {
			t.Errorf("Keep(%d) outside range = true, want false", c)
		}
	}
}

func TestParse_MixedTermsAndWhitespace(t *testing.T) {
	f, err := Parse(" 200 , 500-599 , 302 ,")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cases := map[int]bool{
		200: true,
		302: true,
		404: false,
		499: false,
		500: true,
		599: true,
		600: false, // out of range entirely; never matches
	}
	for c, want := range cases {
		if got := f.Keep(c); got != want {
			t.Errorf("Keep(%d) = %v, want %v", c, got, want)
		}
	}
}

func TestParse_SingleValueRange(t *testing.T) {
	// "500-500" is a degenerate but legal range keeping exactly 500.
	f, err := Parse("500-500")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Keep(500) {
		t.Error("Keep(500) = false, want true")
	}
	if f.Keep(499) || f.Keep(501) {
		t.Error("single-value range kept a neighbour")
	}
}

func TestParse_Errors(t *testing.T) {
	cases := []string{
		"abc",      // non-numeric
		"99",       // below the valid 100 floor
		"600",      // above the valid 599 ceiling
		"0",        // far below floor
		"-5",       // negative (parsed as reversed/empty-low range)
		"599-500",  // reversed range
		"500-",     // missing high bound
		"-",        // empty range
		"500-abc",  // non-numeric high bound
		"50.0",     // float
		"200,oops", // one good, one bad
		"100-600",  // high bound out of range
	}
	for _, spec := range cases {
		if _, err := Parse(spec); err == nil {
			t.Errorf("Parse(%q): expected error, got nil", spec)
		}
	}
}

func TestParse_BoundaryCodes(t *testing.T) {
	// 100 and 599 are the inclusive edges of the valid range.
	f, err := Parse("100,599")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Keep(100) || !f.Keep(599) {
		t.Error("boundary codes 100/599 should be valid and kept")
	}
	if f.Keep(200) {
		t.Error("a code outside the allowlist should be dropped")
	}
}

func TestKeep_Nil(t *testing.T) {
	var f *Filter
	if f.Active() {
		t.Error("nil filter should be inactive")
	}
	// A nil (inactive) filter keeps everything.
	if !f.Keep(200) || !f.Keep(500) {
		t.Error("nil filter should keep everything")
	}
}
