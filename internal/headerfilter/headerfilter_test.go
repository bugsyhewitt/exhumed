package headerfilter

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
		// An inactive filter suppresses nothing, including a nil header map.
		if f.Match(nil) || f.Match(http.Header{"Content-Type": {"text/html"}}) {
			t.Fatalf("Parse(%q): inactive filter should suppress nothing", specs)
		}
	}
}

func TestParse_SinglePairSuppressesMatch(t *testing.T) {
	f, err := Parse([]string{"Content-Type: text/html"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Active() {
		t.Fatal("expected active filter")
	}
	drop := http.Header{"Content-Type": {"text/html; charset=utf-8"}}
	if !f.Match(drop) {
		t.Errorf("Match(%v) = false, want true (should suppress)", drop)
	}
	keep := http.Header{"Content-Type": {"text/plain"}}
	if f.Match(keep) {
		t.Errorf("Match(%v) = true, want false (should keep)", keep)
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
	if !f.Match(h) {
		t.Errorf("case-insensitive header name should match canonical key, Match(%v) = false", h)
	}
}

func TestParse_AbsentHeaderNeverMatches(t *testing.T) {
	f, err := Parse([]string{"X-Cache: HIT"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// The named header is simply not present — an active rule must NOT fire, so
	// the response is kept (not suppressed).
	if f.Match(http.Header{"Content-Type": {"text/html"}}) {
		t.Error("a response missing the named header must not be suppressed")
	}
	if f.Match(nil) {
		t.Error("a nil header map satisfies no rule and must not be suppressed")
	}
}

func TestParse_MultiValueHeaderAnyValueMatches(t *testing.T) {
	// A header with several values fires the rule if ANY value matches the regex.
	f, err := Parse([]string{"Set-Cookie: session"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	h := http.Header{"Set-Cookie": {"theme=dark", "session=abc123"}}
	if !f.Match(h) {
		t.Errorf("any-value match should suppress, Match(%v) = false", h)
	}
	none := http.Header{"Set-Cookie": {"theme=dark", "lang=en"}}
	if f.Match(none) {
		t.Errorf("no value matching should keep, Match(%v) = true", none)
	}
}

func TestParse_MultiplePairsAreDisjunction(t *testing.T) {
	// Two rules: ANY satisfied rule suppresses (disjunction), the deliberate
	// opposite of matchheaders's conjunction. A response is dropped if it matches
	// EITHER noise signature.
	f, err := Parse([]string{
		"Server: cloudflare",
		"X-Cache: HIT",
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Only the first rule matches — disjunction still suppresses.
	onlyServer := http.Header{"Server": {"cloudflare"}}
	if !f.Match(onlyServer) {
		t.Errorf("one rule satisfied should suppress (disjunction), got false")
	}
	// Only the second rule matches — disjunction still suppresses.
	onlyCache := http.Header{"X-Cache": {"HIT from edge"}}
	if !f.Match(onlyCache) {
		t.Errorf("the other rule satisfied should suppress (disjunction), got false")
	}
	// Neither rule matches — kept.
	neither := http.Header{"Server": {"nginx"}, "X-Cache": {"MISS"}}
	if f.Match(neither) {
		t.Errorf("no rule satisfied should keep, got true")
	}
}

func TestParse_RegexSemantics(t *testing.T) {
	// The value side is a full RE2 regex with a contains (unanchored) match.
	f, err := Parse([]string{`Content-Type: text/(html|css)`})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, v := range []string{"text/html", "text/css; charset=utf-8"} {
		h := http.Header{"Content-Type": {v}}
		if !f.Match(h) {
			t.Errorf("regex should match %q, Match = false", v)
		}
	}
	if f.Match(http.Header{"Content-Type": {"text/plain"}}) {
		t.Error("regex should not match text/plain")
	}
}

func TestParse_WhitespaceTrimming(t *testing.T) {
	// Leading whitespace after the colon (a common shell-quoting artefact) is
	// trimmed from both name and pattern.
	f, err := Parse([]string{"  Content-Type :   text/html  "})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Match(http.Header{"Content-Type": {"text/html"}}) {
		t.Error("whitespace-padded spec should still match")
	}
}

func TestParse_Errors(t *testing.T) {
	cases := [][]string{
		{"Content-Type"},      // no colon
		{": text/html"},       // empty header name
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

func TestMatch_Nil(t *testing.T) {
	var f *Filter
	if f.Active() {
		t.Error("nil filter should be inactive")
	}
	// A nil (inactive) filter suppresses nothing.
	if f.Match(nil) || f.Match(http.Header{"Content-Type": {"text/html"}}) {
		t.Error("nil filter should suppress nothing")
	}
}
