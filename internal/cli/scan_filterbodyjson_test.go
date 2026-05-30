package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// filterBodyJSONNoiseFlags builds scanFlags against the curated fixture DB that
// DO emit unconfirmed responses (onlyHits=false), so --filter-body-json is the
// only thing that can suppress the "[responded]" stream. Chaining is disabled
// for determinism. The other suppression filters and the match gates are left
// empty so the negative JSON gate is exercised in isolation.
func filterBodyJSONNoiseFlags(t *testing.T, serverURL string, rules []string) scanFlags {
	return scanFlags{
		url:            serverURL + "/?file=FUZZ",
		marker:         "FUZZ",
		method:         "GET",
		concurrency:    1,
		timeout:        5 * time.Second,
		traversalDepth: 1,
		dbPath:         curatedDBPath(t),
		onlyHits:       false,
		maxDepth:       0,
		maxTargets:     0,
		outputFormat:   "text",
		filterBodyJSON: rules,
	}
}

// TestScan_FilterBodyJSONSuppressesNoise verifies that, without a filter, the
// JSON noise responses appear, and that naming the noise's own JSON field value
// drops them all — the negative twin of --match-body-json.
func TestScan_FilterBodyJSONSuppressesNoise(t *testing.T) {
	srv := jsonNoiseServer(`{"ok":false,"error":"file not found"}`)
	defer srv.Close()

	// Baseline: no filter — the noise should show up.
	baseline := captureStdout(t, func() {
		if err := runScan(filterBodyJSONNoiseFlags(t, srv.URL, nil)); err != nil {
			t.Fatalf("runScan baseline: %v", err)
		}
	})
	if !strings.Contains(baseline, "[responded]") {
		t.Fatalf("baseline produced no [responded] lines:\n%s", baseline)
	}

	// Name the field value the noise carries — every response is suppressed.
	out := captureStdout(t, func() {
		if err := runScan(filterBodyJSONNoiseFlags(t, srv.URL, []string{"ok: false"})); err != nil {
			t.Fatalf("runScan filtered: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--filter-body-json 'ok: false' should drop matching noise, got:\n%s", out)
	}
}

// TestScan_FilterBodyJSONKeepsUnmatched verifies that naming a JSON value the
// noise does NOT carry leaves the unconfirmed responses untouched — only
// matching scalars are suppressed.
func TestScan_FilterBodyJSONKeepsUnmatched(t *testing.T) {
	srv := jsonNoiseServer(`{"ok":true,"content":"hello"}`)
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(filterBodyJSONNoiseFlags(t, srv.URL, []string{"ok: false"})); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("--filter-body-json 'ok: false' should NOT drop ok:true noise, got:\n%s", out)
	}
}

// TestScan_FilterBodyJSONDisjunction verifies multiple --filter-body-json rules
// compose as a disjunction: an unconfirmed response is suppressed if ANY rule
// matches the decoded JSON body.
func TestScan_FilterBodyJSONDisjunction(t *testing.T) {
	rules := []string{
		`ok: false`,
		`error: (?i)not found`,
	}

	// First rule fires (ok:false), second wouldn't (no error field).
	srv1 := jsonNoiseServer(`{"ok":false,"content":null}`)
	defer srv1.Close()
	out1 := captureStdout(t, func() {
		if err := runScan(filterBodyJSONNoiseFlags(t, srv1.URL, rules)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out1, "[responded]") {
		t.Fatalf("first rule should suppress, got:\n%s", out1)
	}

	// Second rule fires (error:Not Found), first wouldn't (ok:true).
	srv2 := jsonNoiseServer(`{"ok":true,"error":"Not Found"}`)
	defer srv2.Close()
	out2 := captureStdout(t, func() {
		if err := runScan(filterBodyJSONNoiseFlags(t, srv2.URL, rules)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out2, "[responded]") {
		t.Fatalf("second rule should suppress, got:\n%s", out2)
	}

	// Neither rule fires.
	srv3 := jsonNoiseServer(`{"ok":true,"content":"all good"}`)
	defer srv3.Close()
	out3 := captureStdout(t, func() {
		if err := runScan(filterBodyJSONNoiseFlags(t, srv3.URL, rules)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out3, "[responded]") {
		t.Fatalf("neither rule matches; should keep, got:\n%s", out3)
	}
}

// TestScan_FilterBodyJSONNonJSONIsKept verifies a response whose body is not
// valid JSON is NOT suppressed even when --filter-body-json is active — the
// suppressor cannot classify a non-JSON body as JSON-shaped noise.
func TestScan_FilterBodyJSONNonJSONIsKept(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(noiseBody)) // plain text, not JSON
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(filterBodyJSONNoiseFlags(t, srv.URL, []string{"ok: false"})); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("a non-JSON body must not be suppressed by --filter-body-json, got:\n%s", out)
	}
}

// TestScan_FilterBodyJSONMissingPathIsKept verifies a JSON body whose schema
// does NOT contain the named path is NOT suppressed.
func TestScan_FilterBodyJSONMissingPathIsKept(t *testing.T) {
	srv := jsonNoiseServer(`{"other":"value"}`)
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(filterBodyJSONNoiseFlags(t, srv.URL, []string{"ok: false"})); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("a JSON body missing the named path must not be suppressed, got:\n%s", out)
	}
}

// TestScan_FilterBodyJSONNeverDropsHits verifies a confirmed hit is reported
// even when --filter-body-json names a regex that would match a value the hit
// would carry (or the hit's body isn't JSON at all). Confirmation is
// content-based and must survive the suppression gate.
func TestScan_FilterBodyJSONNeverDropsHits(t *testing.T) {
	const passwdBody = "root:x:0:0:root:/root:/bin/bash\n" // matches the fixture 'passwd' confirm
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "passwd") {
			// A genuine read — not JSON. The suppressor must not touch it
			// regardless; confirmation is the higher-priority signal.
			_, _ = w.Write([]byte(passwdBody))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":false,"error":"nope"}`))
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(filterBodyJSONNoiseFlags(t, srv.URL, []string{"ok: false"})); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[CONFIRMED]") {
		t.Fatalf("confirmed hit must survive --filter-body-json, got:\n%s", out)
	}
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--filter-body-json should suppress every unconfirmed JSON line, got:\n%s", out)
	}
}

// TestScan_FilterBodyJSONComposesWithFilterCode verifies the suppression family
// composes as a disjunction across surfaces: a response is dropped if either
// --filter-body-json or --filter-code fires.
func TestScan_FilterBodyJSONComposesWithFilterCode(t *testing.T) {
	// JSON body whose `ok` is true — --filter-body-json 'ok: false' will NOT
	// fire on it; --filter-code 200 will.
	srv := jsonNoiseServer(`{"ok":true,"content":"x"}`)
	defer srv.Close()

	f := filterBodyJSONNoiseFlags(t, srv.URL, []string{"ok: false"})
	f.filterCode = "200"
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a response matched by --filter-code must be suppressed regardless of --filter-body-json, got:\n%s", out)
	}
}

// TestScan_FilterBodyJSONComposesWithMatchBodyJSON verifies the match gates
// run BEFORE the suppression filters: --match-body-json keeps the matching
// JSON, then --filter-body-json prunes it back out (the negative twin wins on
// the kept stream).
func TestScan_FilterBodyJSONComposesWithMatchBodyJSON(t *testing.T) {
	srv := jsonNoiseServer(`{"ok":true,"note":"soft-404"}`)
	defer srv.Close()

	f := filterBodyJSONNoiseFlags(t, srv.URL, []string{"note: soft-404"}) // suppress: matches
	f.matchBodyJSON = []string{"ok: true"}                                // keep: also matches
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a response kept by --match-body-json that also matches --filter-body-json must be suppressed, got:\n%s", out)
	}
}

// TestScan_FilterBodyJSONInvalidSpecErrors verifies a malformed
// --filter-body-json value fails before any requests fire.
func TestScan_FilterBodyJSONInvalidSpecErrors(t *testing.T) {
	srv := jsonNoiseServer(`{"ok":true}`)
	defer srv.Close()

	err := runScan(filterBodyJSONNoiseFlags(t, srv.URL, []string{"ok: ["})) // unparsable regex
	if err == nil {
		t.Fatal("expected error for malformed --filter-body-json regex")
	}
	if !strings.Contains(err.Error(), "filterbodyjson") {
		t.Fatalf("unexpected error: %v", err)
	}
}
