package matchbodyjson

import "testing"

// TestParseInactiveOnEmpty verifies that an empty or all-blank spec set yields
// an inactive filter that keeps everything.
func TestParseInactiveOnEmpty(t *testing.T) {
	for _, specs := range [][]string{nil, {}, {""}, {"  ", "\t"}} {
		f, err := Parse(specs)
		if err != nil {
			t.Fatalf("Parse(%q) unexpected error: %v", specs, err)
		}
		if f.Active() {
			t.Fatalf("Parse(%q) should be inactive", specs)
		}
		if !f.Keep([]byte(`{"anything":1}`)) {
			t.Fatalf("inactive filter must keep everything, spec=%q", specs)
		}
		// An inactive filter keeps even non-JSON bodies.
		if !f.Keep([]byte("not json at all")) {
			t.Fatalf("inactive filter must keep non-JSON bodies, spec=%q", specs)
		}
	}
}

// TestParseRejectsMalformed verifies the parse-time validation rejects bad specs
// so the operator learns immediately instead of silently keeping nothing.
func TestParseRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		spec string
	}{
		{"no colon", "okisset"},
		{"empty path", ": true"},
		{"empty regex", "ok: "},
		{"leading dot", ".ok: true"},
		{"trailing dot", "ok.: true"},
		{"doubled dot", "a..b: true"},
		{"dangling escape", `ok\: true`},
		{"bad regex", "ok: ["},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse([]string{c.spec}); err == nil {
				t.Fatalf("Parse(%q) expected error, got nil", c.spec)
			}
		})
	}
}

// TestKeepStringField verifies a regex match against a top-level string field.
func TestKeepStringField(t *testing.T) {
	f, err := Parse([]string{"status: ok"})
	if err != nil {
		t.Fatal(err)
	}
	if !f.Active() {
		t.Fatal("filter should be active")
	}
	if !f.Keep([]byte(`{"status":"ok","x":1}`)) {
		t.Fatal("should keep body whose status field matches")
	}
	if f.Keep([]byte(`{"status":"error"}`)) {
		t.Fatal("should drop body whose status field does not match")
	}
}

// TestKeepBoolField verifies booleans are stringified to true/false so a regex
// can target them.
func TestKeepBoolField(t *testing.T) {
	f, err := Parse([]string{"ok: true"})
	if err != nil {
		t.Fatal(err)
	}
	if !f.Keep([]byte(`{"ok":true}`)) {
		t.Fatal("should keep ok:true")
	}
	if f.Keep([]byte(`{"ok":false}`)) {
		t.Fatal("should drop ok:false")
	}
}

// TestKeepNumberField verifies numeric scalars render without a trailing ".0"
// for integers, so a regex like ^200$ matches an integer JSON value.
func TestKeepNumberField(t *testing.T) {
	f, err := Parse([]string{"code: ^200$"})
	if err != nil {
		t.Fatal(err)
	}
	if !f.Keep([]byte(`{"code":200}`)) {
		t.Fatal("should keep code:200")
	}
	if f.Keep([]byte(`{"code":404}`)) {
		t.Fatal("should drop code:404")
	}

	// Float values render naturally.
	ff, err := Parse([]string{`ratio: ^1\.5$`})
	if err != nil {
		t.Fatal(err)
	}
	if !ff.Keep([]byte(`{"ratio":1.5}`)) {
		t.Fatal("should keep ratio:1.5")
	}
}

// TestKeepNullField verifies a null scalar is matchable as the literal "null".
func TestKeepNullField(t *testing.T) {
	f, err := Parse([]string{"err: ^null$"})
	if err != nil {
		t.Fatal(err)
	}
	if !f.Keep([]byte(`{"err":null}`)) {
		t.Fatal("should keep err:null")
	}
	if f.Keep([]byte(`{"err":"boom"}`)) {
		t.Fatal("should drop err with a non-null value")
	}
}

// TestNestedPath verifies dot-separated object descent.
func TestNestedPath(t *testing.T) {
	f, err := Parse([]string{"data.path: ^/etc/"})
	if err != nil {
		t.Fatal(err)
	}
	if !f.Keep([]byte(`{"data":{"path":"/etc/passwd"}}`)) {
		t.Fatal("should keep nested path /etc/passwd")
	}
	if f.Keep([]byte(`{"data":{"path":"/var/log/x"}}`)) {
		t.Fatal("should drop nested path /var/log/x")
	}
}

// TestArrayIndex verifies a non-negative integer segment indexes a JSON array.
func TestArrayIndex(t *testing.T) {
	f, err := Parse([]string{"results.0.name: passwd"})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"results":[{"name":"passwd"},{"name":"shadow"}]}`)
	if !f.Keep(body) {
		t.Fatal("should keep results[0].name == passwd")
	}
	body2 := []byte(`{"results":[{"name":"shadow"}]}`)
	if f.Keep(body2) {
		t.Fatal("should drop results[0].name == shadow")
	}
	// Out-of-range index never matches.
	if f.Keep([]byte(`{"results":[]}`)) {
		t.Fatal("out-of-range index must not match")
	}
}

// TestMissingPathDrops verifies an absent path never satisfies a rule (the body
// is dropped by an active filter).
func TestMissingPathDrops(t *testing.T) {
	f, err := Parse([]string{"missing: anything"})
	if err != nil {
		t.Fatal(err)
	}
	if f.Keep([]byte(`{"present":"x"}`)) {
		t.Fatal("absent path must not match")
	}
}

// TestNonScalarPathDrops verifies a path landing on an object or array never
// matches, even if the regex would match the serialized container text.
func TestNonScalarPathDrops(t *testing.T) {
	f, err := Parse([]string{"data: .*"})
	if err != nil {
		t.Fatal(err)
	}
	if f.Keep([]byte(`{"data":{"k":"v"}}`)) {
		t.Fatal("object value must not match a scalar rule")
	}
	if f.Keep([]byte(`{"data":[1,2,3]}`)) {
		t.Fatal("array value must not match a scalar rule")
	}
	// A scalar at the same path does match.
	if !f.Keep([]byte(`{"data":"hello"}`)) {
		t.Fatal("scalar value should match .* rule")
	}
}

// TestNonJSONBodyDrops verifies a body that is not valid JSON never satisfies an
// active filter.
func TestNonJSONBodyDrops(t *testing.T) {
	f, err := Parse([]string{"ok: true"})
	if err != nil {
		t.Fatal(err)
	}
	if f.Keep([]byte("<html>not json</html>")) {
		t.Fatal("non-JSON body must be dropped by an active filter")
	}
	if f.Keep(nil) {
		t.Fatal("empty body must be dropped by an active filter")
	}
}

// TestConjunction verifies multiple rules compose as a conjunction: every rule
// must be satisfied.
func TestConjunction(t *testing.T) {
	f, err := Parse([]string{"ok: true", "data.path: ^/etc/"})
	if err != nil {
		t.Fatal(err)
	}
	both := []byte(`{"ok":true,"data":{"path":"/etc/passwd"}}`)
	if !f.Keep(both) {
		t.Fatal("should keep body satisfying both rules")
	}
	onlyFirst := []byte(`{"ok":true,"data":{"path":"/var/x"}}`)
	if f.Keep(onlyFirst) {
		t.Fatal("should drop body satisfying only the first rule")
	}
	onlySecond := []byte(`{"ok":false,"data":{"path":"/etc/passwd"}}`)
	if f.Keep(onlySecond) {
		t.Fatal("should drop body satisfying only the second rule")
	}
}

// TestEscapedDotInKey verifies a literal dot inside an object key is honoured via
// backslash escaping, so the key "a.b" is one segment, not two.
func TestEscapedDotInKey(t *testing.T) {
	f, err := Parse([]string{`a\.b: hit`})
	if err != nil {
		t.Fatal(err)
	}
	if !f.Keep([]byte(`{"a.b":"hit"}`)) {
		t.Fatal("escaped dot should match the literal key a.b")
	}
	// Without the escape, a.b descends two levels and would not find the key.
	g, err := Parse([]string{`a.b: hit`})
	if err != nil {
		t.Fatal(err)
	}
	if g.Keep([]byte(`{"a.b":"hit"}`)) {
		t.Fatal("unescaped a.b must descend, not match the literal key a.b")
	}
}

// TestBlankRepeatTolerated verifies a blank repeated spec is skipped rather than
// fatal, and does not by itself activate the filter.
func TestBlankRepeatTolerated(t *testing.T) {
	f, err := Parse([]string{"", "ok: true", "  "})
	if err != nil {
		t.Fatal(err)
	}
	if !f.Active() {
		t.Fatal("the one real rule should make the filter active")
	}
	if len(f.rules) != 1 {
		t.Fatalf("expected exactly 1 rule, got %d", len(f.rules))
	}
}

// TestNilReceiverKeeps verifies a nil *Filter is treated as inactive.
func TestNilReceiverKeeps(t *testing.T) {
	var f *Filter
	if f.Active() {
		t.Fatal("nil filter must be inactive")
	}
	if !f.Keep([]byte(`{"x":1}`)) {
		t.Fatal("nil filter must keep everything")
	}
}
