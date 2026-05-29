package matchfilter

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
		if !f.Keep([]byte("anything")) || !f.Keep(nil) {
			t.Fatalf("Parse(%q): inactive filter should keep everything", spec)
		}
	}
}

func TestParse_LiteralContainsKept(t *testing.T) {
	f, err := Parse("password")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Active() {
		t.Fatal("expected active filter")
	}
	keep := [][]byte{
		[]byte("password"),
		[]byte("db_password=hunter2"),
		[]byte("the password field is here"),
	}
	for _, b := range keep {
		if !f.Keep(b) {
			t.Errorf("Keep(%q) = false, want true", b)
		}
	}
	drop := [][]byte{
		[]byte("root:x:0:0:root:/root:/bin/bash"),
		[]byte("PASSWORD"), // case differs
		[]byte(""),
		nil,
	}
	for _, b := range drop {
		if f.Keep(b) {
			t.Errorf("Keep(%q) = true, want false", b)
		}
	}
}

func TestParse_CaseInsensitive(t *testing.T) {
	f, err := Parse("(?i)secret")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, b := range []string{"Secret", "SECRET", "topsecret"} {
		if !f.Keep([]byte(b)) {
			t.Errorf("Keep(%q) = false, want true", b)
		}
	}
	if f.Keep([]byte("nothing here")) {
		t.Error("Keep(nothing here) = true, want false")
	}
}

func TestParse_Alternation(t *testing.T) {
	// A typical recon pattern: keep responses that name any secret-ish marker.
	f, err := Parse(`(?i)password|secret|api[_-]?key`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	keep := []string{"Password:", "client_secret", "API_KEY", "api-key", "apikey"}
	for _, b := range keep {
		if !f.Keep([]byte(b)) {
			t.Errorf("Keep(%q) = false, want true", b)
		}
	}
	if f.Keep([]byte("just an ordinary page")) {
		t.Error("non-matching body should be dropped")
	}
}

func TestParse_Anchored(t *testing.T) {
	// An explicitly whole-body-anchored pattern only keeps an exact body.
	f, err := Parse("^OK$")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Keep([]byte("OK")) {
		t.Error("Keep(OK) = false, want true")
	}
	if f.Keep([]byte("OK then")) {
		t.Error("anchored pattern kept a longer body")
	}
}

func TestParse_PreservesInnerWhitespace(t *testing.T) {
	// Leading/trailing whitespace is trimmed, but whitespace inside the pattern
	// is significant and preserved.
	f, err := Parse("  a b  ")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Keep([]byte("xx a b yy")) {
		t.Error(`Keep should find "a b" with its inner space preserved`)
	}
	if f.Keep([]byte("ab")) {
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

func TestKeep_Nil(t *testing.T) {
	var f *Filter
	if f.Active() {
		t.Error("nil filter should be inactive")
	}
	// A nil (inactive) filter keeps everything.
	if !f.Keep([]byte("password")) || !f.Keep(nil) {
		t.Error("nil filter should keep everything")
	}
}

func TestKeep_MultilineBody(t *testing.T) {
	// By default '.' does not cross newlines, but a literal phrase on one line of
	// a multi-line body is still found.
	f, err := Parse("interesting")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	body := []byte("line one\nthe interesting bit is here\nline three")
	if !f.Keep(body) {
		t.Error("Keep across multi-line body = false, want true")
	}
	if f.Keep([]byte("line one\nline two\nline three")) {
		t.Error("body with no match should be dropped")
	}
}
