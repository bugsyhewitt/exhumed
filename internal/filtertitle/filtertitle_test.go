package filtertitle

import (
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
		// An inactive suppression filter suppresses nothing, including a body
		// with a title that would otherwise match.
		for _, body := range [][]byte{
			nil,
			[]byte("<title>404 Not Found</title>"),
			[]byte("<html><body>no title</body></html>"),
		} {
			if f.MatchBody(body) {
				t.Fatalf("Parse(%q): inactive filter should suppress nothing, got Match=true for %q", specs, body)
			}
		}
	}
}

func TestMatchBody_SingleSpecSuppressesMatch(t *testing.T) {
	f, err := Parse([]string{"404 Not Found"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Active() {
		t.Fatal("expected active filter")
	}
	drop := []byte(`<html><head><title>404 Not Found</title></head></html>`)
	if !f.MatchBody(drop) {
		t.Errorf("MatchBody on matching title returned false (should suppress)")
	}
	keep := []byte(`<html><head><title>Index of /etc</title></head><body>...</body></html>`)
	if f.MatchBody(keep) {
		t.Errorf("MatchBody on non-matching title returned true (should keep)")
	}
}

func TestMatchBody_CaseInsensitiveRegex(t *testing.T) {
	f, err := Parse([]string{`(?i)access denied|forbidden`})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, body := range []string{
		`<title>ACCESS DENIED</title>`,
		`<title>403 Forbidden</title>`,
		`<title>access denied — please log in</title>`,
	} {
		if !f.MatchBody([]byte(body)) {
			t.Errorf("case-insensitive regex should suppress %q", body)
		}
	}
}

func TestMatchBody_NoTitleNeverSuppresses(t *testing.T) {
	// A body without an extractable title cannot satisfy a title-shape
	// signature, so an active --filter-title leaves it alone. The operator
	// can combine with --match-title or another --filter-* flag to drop it
	// if desired.
	f, err := Parse([]string{"anything"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, body := range [][]byte{
		nil,
		[]byte(""),
		[]byte(`<html><body>no title at all</body></html>`),
		[]byte(`{"json":"body","title":"in JSON, not HTML"}`),
		[]byte(`<title>truncated before close`), // no closing tag
	} {
		if f.MatchBody(body) {
			t.Errorf("a body without an extractable title must not be suppressed, got Match=true for %q", body)
		}
	}
}

func TestMatchBody_MultipleSpecsAreDisjunction(t *testing.T) {
	// Two rules: suppress if EITHER matches. This is the opposite of
	// matchtitle's conjunction and mirrors the rest of the --filter-* family.
	f, err := Parse([]string{
		`404 Not Found`,
		`(?i)access denied`,
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, body := range []string{
		`<title>404 Not Found</title>`,                 // first rule matches
		`<title>ACCESS DENIED</title>`,                 // second rule matches
		`<title>404 Not Found — Access Denied</title>`, // both match
	} {
		if !f.MatchBody([]byte(body)) {
			t.Errorf("disjunction should suppress %q", body)
		}
	}
	keep := []byte(`<title>Index of /etc</title>`)
	if f.MatchBody(keep) {
		t.Errorf("neither rule matches %q — should be kept", keep)
	}
}

func TestMatchBody_AppliesExtractorNormalisation(t *testing.T) {
	// The extractor decodes entities and collapses whitespace before the regex
	// runs, so a spec written against the visible title form matches.
	f, err := Parse([]string{`foo & bar`})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	body := []byte(`<title>foo &amp; bar</title>`)
	if !f.MatchBody(body) {
		t.Errorf("entity-decoded title should match spec against visible form")
	}

	f2, err := Parse([]string{`Index of /etc/`})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	body2 := []byte("<title>\n  Index of\t/etc/\n</title>")
	if !f2.MatchBody(body2) {
		t.Errorf("whitespace-collapsed title should match visible-form spec")
	}
}

func TestMatchBody_AttributesAndCase(t *testing.T) {
	// The extractor is permissive on tag case and intra-tag attributes; the
	// suppressor inherits that.
	f, err := Parse([]string{`Forbidden`})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, body := range []string{
		`<TITLE>403 Forbidden</TITLE>`,
		`<Title id="page" class="err">403 Forbidden</Title>`,
	} {
		if !f.MatchBody([]byte(body)) {
			t.Errorf("extractor permissiveness should let %q be suppressed", body)
		}
	}
}

func TestMatchBody_FirstTitleWins(t *testing.T) {
	// Pathological multi-title documents: the extractor takes the first; the
	// suppressor inherits.
	f, err := Parse([]string{`^Real$`})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	body := []byte(`<title>Real</title><title>Decoy</title>`)
	if !f.MatchBody(body) {
		t.Error("first <title> should be the source of truth")
	}
}

func TestParse_Errors(t *testing.T) {
	cases := [][]string{
		{"["},                 // unparsable regex
		{"good", "(unclosed"}, // one good, one bad
		{"(?P<x>good)", "*bad"},
	}
	for _, specs := range cases {
		if _, err := Parse(specs); err == nil {
			t.Errorf("Parse(%q): expected error, got nil", specs)
		}
	}
}

func TestMatchBody_NilFilter(t *testing.T) {
	var f *Filter
	if f.Active() {
		t.Error("nil filter should be inactive")
	}
	if f.MatchBody(nil) || f.MatchBody([]byte("<title>x</title>")) {
		t.Error("nil filter should suppress nothing")
	}
}
