package codefilter

import "testing"

func TestParse_Empty(t *testing.T) {
	for _, spec := range []string{"", "   ", "\t"} {
		f, err := Parse(spec)
		if err != nil {
			t.Fatalf("Parse(%q): unexpected error: %v", spec, err)
		}
		if f.Active() {
			t.Fatalf("Parse(%q): expected inactive filter", spec)
		}
		if f.Match(404) || f.Match(200) {
			t.Fatalf("Parse(%q): inactive filter matched", spec)
		}
	}
}

func TestParse_ExactCodes(t *testing.T) {
	f, err := Parse("403,404,500")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Active() {
		t.Fatal("expected active filter")
	}
	for _, c := range []int{403, 404, 500} {
		if !f.Match(c) {
			t.Errorf("Match(%d) = false, want true", c)
		}
	}
	for _, c := range []int{200, 301, 402, 405, 499, 501} {
		if f.Match(c) {
			t.Errorf("Match(%d) = true, want false", c)
		}
	}
}

func TestParse_Range(t *testing.T) {
	f, err := Parse("400-499")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, c := range []int{400, 404, 451, 499} {
		if !f.Match(c) {
			t.Errorf("Match(%d) in range = false, want true", c)
		}
	}
	for _, c := range []int{399, 500} {
		if f.Match(c) {
			t.Errorf("Match(%d) outside range = true, want false", c)
		}
	}
}

func TestParse_MixedTermsAndWhitespace(t *testing.T) {
	f, err := Parse(" 302 , 400-499 , 500 ,")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cases := map[int]bool{
		200: false,
		302: true,
		400: true,
		404: true,
		499: true,
		500: true,
		501: false,
	}
	for c, want := range cases {
		if got := f.Match(c); got != want {
			t.Errorf("Match(%d) = %v, want %v", c, got, want)
		}
	}
}

func TestParse_SingleValueRange(t *testing.T) {
	// "404-404" is a degenerate but legal range matching exactly 404.
	f, err := Parse("404-404")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Match(404) {
		t.Error("Match(404) = false, want true")
	}
	if f.Match(403) || f.Match(405) {
		t.Error("single-value range matched neighbour")
	}
}

func TestParse_Errors(t *testing.T) {
	cases := []string{
		"abc",      // non-numeric
		"99",       // below the valid 100 floor
		"600",      // above the valid 599 ceiling
		"0",        // far below floor
		"-5",       // negative (parsed as reversed/empty-low range)
		"500-400",  // reversed range
		"400-",     // missing high bound
		"-",        // empty range
		"400-abc",  // non-numeric high bound
		"40.4",     // float
		"404,oops", // one good, one bad
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
	if !f.Match(100) || !f.Match(599) {
		t.Error("boundary codes 100/599 should be valid and match")
	}
}

func TestMatch_Nil(t *testing.T) {
	var f *Filter
	if f.Active() {
		t.Error("nil filter should be inactive")
	}
	if f.Match(404) {
		t.Error("nil filter should not match")
	}
}
