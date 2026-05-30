package filterbodyjson

import "testing"

// TestParse_Empty verifies that an empty or all-blank spec set yields an
// inactive filter that suppresses nothing.
func TestParse_Empty(t *testing.T) {
	for _, specs := range [][]string{nil, {}, {""}, {"  ", "\t"}} {
		f, err := Parse(specs)
		if err != nil {
			t.Fatalf("Parse(%q): unexpected error: %v", specs, err)
		}
		if f.Active() {
			t.Fatalf("Parse(%q): expected inactive filter", specs)
		}
		// An inactive suppression filter suppresses nothing, including a JSON
		// body that would otherwise match.
		for _, body := range [][]byte{
			nil,
			[]byte(`{"ok":false}`),
			[]byte(`not json at all`),
		} {
			if f.MatchBody(body) {
				t.Fatalf("Parse(%q): inactive filter should suppress nothing, got Match=true for %q", specs, body)
			}
		}
	}
}

// TestParse_Errors verifies the parse-time validation rejects bad specs so the
// operator learns immediately instead of silently filtering nothing.
func TestParse_Errors(t *testing.T) {
	cases := []struct {
		name string
		spec string
	}{
		{"no colon", "okisset"},
		{"empty path", ": false"},
		{"empty regex", "ok: "},
		{"leading dot", ".ok: false"},
		{"trailing dot", "ok.: false"},
		{"doubled dot", "a..b: false"},
		{"dangling escape", `ok\: false`},
		{"bad regex", "ok: ["},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse([]string{c.spec}); err == nil {
				t.Fatalf("Parse(%q): expected error, got nil", c.spec)
			}
		})
	}
}

// TestMatchBody_SingleRuleSuppressesMatch verifies that naming a noise value at
// a path drops every response that carries it.
func TestMatchBody_SingleRuleSuppressesMatch(t *testing.T) {
	f, err := Parse([]string{"ok: false"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.Active() {
		t.Fatal("expected active filter")
	}
	drop := []byte(`{"ok":false,"error":"not found"}`)
	if !f.MatchBody(drop) {
		t.Errorf("MatchBody on matching scalar returned false (should suppress)")
	}
	keep := []byte(`{"ok":true,"content":"hello"}`)
	if f.MatchBody(keep) {
		t.Errorf("MatchBody on non-matching scalar returned true (should keep)")
	}
}

// TestMatchBody_CaseInsensitiveRegex confirms RE2 (?i) flags work inside the
// scalar regex.
func TestMatchBody_CaseInsensitiveRegex(t *testing.T) {
	f, err := Parse([]string{`error: (?i)not found|forbidden`})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, body := range []string{
		`{"error":"NOT FOUND"}`,
		`{"error":"forbidden"}`,
		`{"error":"file not found in webroot"}`,
	} {
		if !f.MatchBody([]byte(body)) {
			t.Errorf("case-insensitive regex should suppress %q", body)
		}
	}
}

// TestMatchBody_NonJSONNeverSuppresses verifies that a body which is not valid
// JSON is NOT suppressed by an active filter. A JSON suppressor cannot
// classify a non-JSON body as JSON-shaped noise.
func TestMatchBody_NonJSONNeverSuppresses(t *testing.T) {
	f, err := Parse([]string{"ok: false"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, body := range [][]byte{
		nil,
		[]byte(""),
		[]byte(`<html><title>404</title></html>`),
		[]byte(`not json at all`),
		[]byte(`{"ok": tru`), // truncated/invalid JSON
	} {
		if f.MatchBody(body) {
			t.Errorf("a non-JSON body must not be suppressed, got Match=true for %q", body)
		}
	}
}

// TestMatchBody_MissingPathOrNonScalarNeverSuppresses verifies that a body
// whose JSON does not contain the named path, or whose path lands on an object
// or array, is NOT suppressed.
func TestMatchBody_MissingPathOrNonScalarNeverSuppresses(t *testing.T) {
	f, err := Parse([]string{"data.path: ^/etc"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, body := range []string{
		`{"other":"value"}`,            // path missing entirely
		`{"data":{"other":"value"}}`,   // partial path resolves, leaf missing
		`{"data":{"path":{"x":"y"}}}`,  // path lands on object, not scalar
		`{"data":{"path":["/etc/x"]}}`, // path lands on array, not scalar
	} {
		if f.MatchBody([]byte(body)) {
			t.Errorf("missing or non-scalar path must not suppress, got Match=true for %q", body)
		}
	}
}

// TestMatchBody_MultipleRulesAreDisjunction verifies multiple --filter-body-json
// rules compose as a disjunction: a response is suppressed if ANY rule fires.
// This is the opposite of matchbodyjson's conjunction and mirrors the rest of
// the --filter-* family.
func TestMatchBody_MultipleRulesAreDisjunction(t *testing.T) {
	f, err := Parse([]string{
		`ok: false`,
		`error: (?i)not found`,
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, body := range []string{
		`{"ok":false,"content":"x"}`,       // first rule matches
		`{"ok":true,"error":"NOT FOUND"}`,  // second rule matches
		`{"ok":false,"error":"not found"}`, // both match
	} {
		if !f.MatchBody([]byte(body)) {
			t.Errorf("disjunction should suppress %q", body)
		}
	}
	keep := []byte(`{"ok":true,"content":"hello"}`)
	if f.MatchBody(keep) {
		t.Errorf("neither rule matches %q — should be kept", keep)
	}
}

// TestMatchBody_ScalarStringificationKinds verifies the suppressor inherits
// matchbodyjson's stringification rules: strings verbatim, booleans
// "true"/"false", numbers via 'g' (no trailing .0 for integers), null as
// "null".
func TestMatchBody_ScalarStringificationKinds(t *testing.T) {
	cases := []struct {
		name string
		spec string
		body string
	}{
		{"bool true", "ok: true", `{"ok":true}`},
		{"bool false", "ok: false", `{"ok":false}`},
		{"int as 200 not 200.0", "code: ^200$", `{"code":200}`},
		{"float", "rate: 1.5", `{"rate":1.5}`},
		{"null literal", "value: null", `{"value":null}`},
		{"string verbatim", "msg: hello", `{"msg":"hello"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := Parse([]string{c.spec})
			if err != nil {
				t.Fatalf("Parse(%q): %v", c.spec, err)
			}
			if !f.MatchBody([]byte(c.body)) {
				t.Errorf("spec %q must suppress %q", c.spec, c.body)
			}
		})
	}
}

// TestMatchBody_NestedAndArrayPath verifies dot-path descent through objects
// and array index segments.
func TestMatchBody_NestedAndArrayPath(t *testing.T) {
	f, err := Parse([]string{`results.0.status: ^404$`})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	drop := []byte(`{"results":[{"status":404,"name":"miss"}]}`)
	if !f.MatchBody(drop) {
		t.Errorf("nested array-indexed path must suppress %q", drop)
	}
	keep := []byte(`{"results":[{"status":200,"name":"hit"}]}`)
	if f.MatchBody(keep) {
		t.Errorf("nested array-indexed path must keep non-matching %q", keep)
	}
}

// TestMatchBody_EscapedDotInKey verifies a literal dot inside an object key is
// treated as one segment when escaped (`a\.b`).
func TestMatchBody_EscapedDotInKey(t *testing.T) {
	f, err := Parse([]string{`a\.b: noise`})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	body := []byte(`{"a.b":"this is noise"}`)
	if !f.MatchBody(body) {
		t.Errorf("escaped-dot key path must resolve and suppress %q", body)
	}
	// The unescaped form `a.b` must NOT resolve in that body (no nested `a`).
	f2, err := Parse([]string{`a.b: noise`})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if f2.MatchBody(body) {
		t.Errorf("unescaped a.b should NOT resolve in a flat {\"a.b\":...} body")
	}
}

// TestMatchBody_NilFilter verifies the zero value is safe to use.
func TestMatchBody_NilFilter(t *testing.T) {
	var f *Filter
	if f.Active() {
		t.Error("nil filter should be inactive")
	}
	if f.MatchBody(nil) || f.MatchBody([]byte(`{"ok":false}`)) {
		t.Error("nil filter should suppress nothing")
	}
}
