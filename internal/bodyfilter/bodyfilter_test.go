package bodyfilter

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
		if f.Match([]byte("anything")) || f.Match(nil) {
			t.Fatalf("Parse(%q): inactive filter matched", spec)
		}
	}
}

func TestParse_LiteralContains(t *testing.T) {
	f, err := Parse("Not Found")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Active() {
		t.Fatal("expected active filter")
	}
	matching := [][]byte{
		[]byte("Not Found"),
		[]byte("<h1>404 Not Found</h1>"),
		[]byte("prefix Not Found suffix"),
	}
	for _, b := range matching {
		if !f.Match(b) {
			t.Errorf("Match(%q) = false, want true", b)
		}
	}
	nonMatching := [][]byte{
		[]byte("root:x:0:0:root:/root:/bin/bash"),
		[]byte("not found"), // case differs
		[]byte(""),
		nil,
	}
	for _, b := range nonMatching {
		if f.Match(b) {
			t.Errorf("Match(%q) = true, want false", b)
		}
	}
}

func TestParse_CaseInsensitive(t *testing.T) {
	f, err := Parse("(?i)access denied")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, b := range []string{"Access Denied", "ACCESS DENIED", "access denied"} {
		if !f.Match([]byte(b)) {
			t.Errorf("Match(%q) = false, want true", b)
		}
	}
	if f.Match([]byte("granted")) {
		t.Error("Match(granted) = true, want false")
	}
}

func TestParse_Anchored(t *testing.T) {
	// An explicitly whole-body-anchored pattern only matches an exact body.
	f, err := Parse("^OK$")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Match([]byte("OK")) {
		t.Error("Match(OK) = false, want true")
	}
	if f.Match([]byte("OK then")) {
		t.Error("anchored pattern matched a longer body")
	}
}

func TestParse_PreservesInnerWhitespace(t *testing.T) {
	// Leading/trailing whitespace is trimmed, but whitespace inside the pattern
	// is significant and preserved.
	f, err := Parse("  a b  ")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Match([]byte("xx a b yy")) {
		t.Error(`Match should find "a b" with its inner space preserved`)
	}
	if f.Match([]byte("ab")) {
		t.Error("inner space should not have been trimmed away")
	}
}

func TestParse_InvalidRegex(t *testing.T) {
	cases := []string{
		"(unclosed",
		"a[b",
		"*nostart",
		"a{2,1}", // reversed repeat count
		"[z-a]",  // reversed character-class range
		`\`,      // trailing backslash
	}
	for _, spec := range cases {
		if _, err := Parse(spec); err == nil {
			t.Errorf("Parse(%q): expected error, got nil", spec)
		}
	}
}

func TestMatch_Nil(t *testing.T) {
	var f *Filter
	if f.Active() {
		t.Error("nil filter should be inactive")
	}
	if f.Match([]byte("Not Found")) {
		t.Error("nil filter should not match")
	}
}

func TestMatch_MultilineBody(t *testing.T) {
	// By default '.' does not cross newlines, but a literal phrase on one line of
	// a multi-line body is still found.
	f, err := Parse("error page")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	body := []byte("line one\nthe error page is here\nline three")
	if !f.Match(body) {
		t.Error("Match across multi-line body = false, want true")
	}
}
