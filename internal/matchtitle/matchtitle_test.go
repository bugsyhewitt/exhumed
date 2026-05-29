package matchtitle

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
		// An inactive match filter keeps everything, including a body with no title.
		if !f.KeepBody(nil) || !f.KeepBody([]byte("<html>no title here</html>")) {
			t.Fatalf("Parse(%q): inactive filter should keep everything", specs)
		}
	}
}

func TestParse_SingleSpecKeepsMatch(t *testing.T) {
	f, err := Parse([]string{"Index of"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Active() {
		t.Fatal("expected active filter")
	}
	keep := []byte(`<html><head><title>Index of /etc</title></head><body>...</body></html>`)
	if !f.KeepBody(keep) {
		t.Errorf("KeepBody on matching title returned false")
	}
	drop := []byte(`<html><head><title>404 Not Found</title></head></html>`)
	if f.KeepBody(drop) {
		t.Errorf("KeepBody on non-matching title returned true")
	}
}

func TestParse_CaseInsensitiveRegex(t *testing.T) {
	// The operator uses RE2's (?i) flag; the extractor preserves the title's
	// original case.
	f, err := Parse([]string{`(?i)passwd|shadow`})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, body := range []string{
		`<title>/etc/PASSWD viewer</title>`,
		`<title>Shadow file</title>`,
		`<title>passwd contents</title>`,
	} {
		if !f.KeepBody([]byte(body)) {
			t.Errorf("case-insensitive regex should match %q", body)
		}
	}
}

func TestKeepBody_NoTitleNeverMatches(t *testing.T) {
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
		if f.KeepBody(body) {
			t.Errorf("a body without an extractable title must be dropped, got Keep=true for %q", body)
		}
	}
}

func TestParse_MultipleSpecsAreConjunction(t *testing.T) {
	// Two rules: BOTH must match the same extracted title.
	f, err := Parse([]string{
		`(?i)index of`,
		`/etc`,
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	both := []byte(`<title>Index of /etc/</title>`)
	if !f.KeepBody(both) {
		t.Error("both rules satisfied should keep")
	}
	onlyOne := []byte(`<title>Index of /home/</title>`)
	if f.KeepBody(onlyOne) {
		t.Error("one rule unsatisfied should drop")
	}
}

func TestExtractTitle_BasicCases(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
		ok   bool
	}{
		{"simple", `<title>Hello</title>`, "Hello", true},
		{"with attributes", `<title id="x" class="page">Hello</title>`, "Hello", true},
		{"uppercase tag", `<TITLE>Hello</TITLE>`, "Hello", true},
		{"mixed case", `<Title>Hello</Title>`, "Hello", true},
		{"empty title", `<title></title>`, "", true},
		{"no title", `<html><body>x</body></html>`, "", false},
		{"unclosed", `<title>unclosed`, "", false},
		{"first wins", `<title>First</title><title>Second</title>`, "First", true},
	}
	for _, c := range cases {
		got, ok := ExtractTitle([]byte(c.body))
		if got != c.want || ok != c.ok {
			t.Errorf("%s: ExtractTitle = (%q, %v), want (%q, %v)", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestExtractTitle_WhitespaceCollapsing(t *testing.T) {
	// Templates emit newlines and tabs inside <title>; the extractor collapses
	// them to a single space and trims edges, so an operator regex can be
	// written against the visible form.
	body := "<title>\n  Index of\t/etc/\n</title>"
	got, ok := ExtractTitle([]byte(body))
	if !ok {
		t.Fatal("expected ok=true")
	}
	if got != "Index of /etc/" {
		t.Errorf("whitespace not collapsed: got %q", got)
	}
}

func TestExtractTitle_EntityDecoding(t *testing.T) {
	cases := []struct {
		body string
		want string
	}{
		{`<title>foo &amp; bar</title>`, "foo & bar"},
		{`<title>&lt;script&gt;</title>`, "<script>"},
		{`<title>quote: &quot;hi&quot;</title>`, `quote: "hi"`},
		{`<title>&#47;etc&#47;passwd</title>`, "/etc/passwd"},
		{`<title>&#x2F;etc&#x2F;passwd</title>`, "/etc/passwd"},
		{`<title>unknown &nbsp; left</title>`, "unknown &nbsp; left"}, // unknown entity verbatim
	}
	for _, c := range cases {
		got, ok := ExtractTitle([]byte(c.body))
		if !ok {
			t.Errorf("expected ok for %q", c.body)
			continue
		}
		if got != c.want {
			t.Errorf("entity decode of %q: got %q, want %q", c.body, got, c.want)
		}
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

func TestKeepBody_NilFilter(t *testing.T) {
	var f *Filter
	if f.Active() {
		t.Error("nil filter should be inactive")
	}
	if !f.KeepBody(nil) || !f.KeepBody([]byte("<title>x</title>")) {
		t.Error("nil filter should keep everything")
	}
}
