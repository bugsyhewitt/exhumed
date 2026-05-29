package respfilter

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
		if f.Match(0) || f.Match(1000) {
			t.Fatalf("Parse(%q): inactive filter matched", spec)
		}
	}
}

func TestParse_ExactSizes(t *testing.T) {
	f, err := Parse("0,413,1500")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Active() {
		t.Fatal("expected active filter")
	}
	for _, n := range []int{0, 413, 1500} {
		if !f.Match(n) {
			t.Errorf("Match(%d) = false, want true", n)
		}
	}
	for _, n := range []int{1, 412, 414, 1499, 1501} {
		if f.Match(n) {
			t.Errorf("Match(%d) = true, want false", n)
		}
	}
}

func TestParse_Range(t *testing.T) {
	f, err := Parse("100-200")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, n := range []int{100, 150, 200} {
		if !f.Match(n) {
			t.Errorf("Match(%d) in range = false, want true", n)
		}
	}
	for _, n := range []int{99, 201} {
		if f.Match(n) {
			t.Errorf("Match(%d) outside range = true, want false", n)
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
		9000: false,
	}
	for n, want := range cases {
		if got := f.Match(n); got != want {
			t.Errorf("Match(%d) = %v, want %v", n, got, want)
		}
	}
}

func TestParse_SingleValueRange(t *testing.T) {
	// "5-5" is a degenerate but legal range matching exactly 5.
	f, err := Parse("5-5")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Match(5) {
		t.Error("Match(5) = false, want true")
	}
	if f.Match(4) || f.Match(6) {
		t.Error("single-value range matched neighbour")
	}
}

func TestParse_Errors(t *testing.T) {
	cases := []string{
		"abc",      // non-numeric
		"-5",       // negative (parsed as reversed/empty-low range)
		"100-50",   // reversed range
		"10-",      // missing high bound
		"-",        // empty range
		"10-abc",   // non-numeric high bound
		"1.5",      // float
		"100,oops", // one good, one bad
	}
	for _, spec := range cases {
		if _, err := Parse(spec); err == nil {
			t.Errorf("Parse(%q): expected error, got nil", spec)
		}
	}
}

func TestMatch_NilAndNegative(t *testing.T) {
	var f *Filter
	if f.Active() {
		t.Error("nil filter should be inactive")
	}
	if f.Match(10) {
		t.Error("nil filter should not match")
	}

	g, _ := Parse("0")
	if g.Match(-1) {
		t.Error("negative length should never match")
	}
}
