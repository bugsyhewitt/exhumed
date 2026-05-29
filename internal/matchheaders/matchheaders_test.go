package matchheaders

import (
	"net/http"
	"testing"
)

func TestParse_Empty(t *testing.T) {
	for _, specs := range [][]string{nil, {}, {""}, {"  ", "\t"}} {
		f, err := Parse(specs)
		if err != nil {
			t.Fatalf("Parse(%q): unexpected error: %v", specs, err)
		}
		if f.Active() {
			t.Fatalf("Parse(%q): expected inactive filter", specs)
		}
		// An inactive match filter keeps everything, including a nil header map.
		if !f.Keep(nil) || !f.Keep(http.Header{"Content-Type": {"text/html"}}) {
			t.Fatalf("Parse(%q): inactive filter should keep everything", specs)
		}
	}
}

func TestParse_SinglePairKeepsMatch(t *testing.T) {
	f, err := Parse([]string{"Content-Type: text/plain"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Active() {
		t.Fatal("expected active filter")
	}
	keep := http.Header{"Content-Type": {"text/plain; charset=utf-8"}}
	if !f.Keep(keep) {
		t.Errorf("Keep(%v) = false, want true", keep)
	}
	drop := http.Header{"Content-Type": {"text/html"}}
	if f.Keep(drop) {
		t.Errorf("Keep(%v) = true, want false", drop)
	}
}

func TestParse_CaseInsensitiveHeaderName(t *testing.T) {
	// The header name in the spec is canonicalised, so a lower/odd-cased spec
	// still matches the canonical key the engine produces.
	f, err := Parse([]string{"content-TYPE: x-php"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	h := http.Header{"Content-Type": {"text/x-php"}}
	if !f.Keep(h) {
		t.Errorf("case-insensitive header name should match canonical key, Keep(%v) = false", h)
	}
}

func TestParse_AbsentHeaderNeverMatches(t *testing.T) {
	f, err := Parse([]string{"X-Powered-By: PHP"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// The named header is simply not present — an active rule must drop it.
	if f.Keep(http.Header{"Content-Type": {"text/html"}}) {
		t.Error("a response missing the required header must not be kept")
	}
	if f.Keep(nil) {
		t.Error("a nil header map satisfies no rule and must not be kept")
	}
}

func TestParse_MultiValueHeaderAnyValueMatches(t *testing.T) {
	// A header with several values is kept if ANY value matches the regex.
	f, err := Parse([]string{"Set-Cookie: session"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	h := http.Header{"Set-Cookie": {"theme=dark", "session=abc123"}}
	if !f.Keep(h) {
		t.Errorf("any-value match should keep Keep(%v) = false", h)
	}
	none := http.Header{"Set-Cookie": {"theme=dark", "lang=en"}}
	if f.Keep(none) {
		t.Errorf("no value matching should drop Keep(%v) = true", none)
	}
}

func TestParse_MultiplePairsAreConjunction(t *testing.T) {
	// Two rules: BOTH must be satisfied (conjunction), mirroring the rest of the
	// match family.
	f, err := Parse([]string{
		"Content-Type: text/plain",
		"X-Powered-By: PHP",
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	both := http.Header{
		"Content-Type": {"text/plain"},
		"X-Powered-By": {"PHP/8.2"},
	}
	if !f.Keep(both) {
		t.Errorf("both rules satisfied should keep, got false")
	}
	onlyOne := http.Header{
		"Content-Type": {"text/plain"},
		// X-Powered-By absent — the conjunction must fail.
	}
	if f.Keep(onlyOne) {
		t.Errorf("one rule unsatisfied should drop, got true")
	}
}

func TestParse_RegexSemantics(t *testing.T) {
	// The value side is a full RE2 regex with a contains (unanchored) match.
	f, err := Parse([]string{`Content-Type: (text/(plain|x-php)|application/octet-stream)`})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, v := range []string{"text/plain", "application/octet-stream", "text/x-php; charset=utf-8"} {
		h := http.Header{"Content-Type": {v}}
		if !f.Keep(h) {
			t.Errorf("regex should match %q, Keep = false", v)
		}
	}
	if f.Keep(http.Header{"Content-Type": {"text/html"}}) {
		t.Error("regex should not match text/html")
	}
}

func TestParse_WhitespaceTrimming(t *testing.T) {
	// Leading whitespace after the colon (a common shell-quoting artefact) is
	// trimmed from both name and pattern.
	f, err := Parse([]string{"  Content-Type :   text/plain  "})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Keep(http.Header{"Content-Type": {"text/plain"}}) {
		t.Error("whitespace-padded spec should still match")
	}
}

func TestParse_Errors(t *testing.T) {
	cases := [][]string{
		{"Content-Type"},      // no colon
		{": text/plain"},      // empty header name
		{"Content-Type:"},     // empty regex
		{"Content-Type:   "},  // whitespace-only regex
		{"Content-Type: ["},   // unparsable regex
		{"X-Good: ok", "bad"}, // one good, one bad
	}
	for _, specs := range cases {
		if _, err := Parse(specs); err == nil {
			t.Errorf("Parse(%q): expected error, got nil", specs)
		}
	}
}

func TestKeep_Nil(t *testing.T) {
	var f *Filter
	if f.Active() {
		t.Error("nil filter should be inactive")
	}
	// A nil (inactive) filter keeps everything.
	if !f.Keep(nil) || !f.Keep(http.Header{"Content-Type": {"text/html"}}) {
		t.Error("nil filter should keep everything")
	}
}
