package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// matchBodyJSONNoiseFlags builds scanFlags against the curated fixture DB that DO
// emit unconfirmed responses (onlyHits=false), so --match-body-json is the only
// thing governing the "[responded]" stream. Chaining is disabled for
// determinism. The suppression filters and the other match gates are left empty
// so the positive JSON gate is exercised in isolation.
func matchBodyJSONNoiseFlags(t *testing.T, serverURL string, rules []string) scanFlags {
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
		matchBodyJSON:  rules,
	}
}

// jsonNoiseServer returns the given JSON envelope (a soft-404 style response) for
// every miss, simulating a JSON-API endpoint whose "not found" reply is a stable
// JSON document. The body is long enough to clear detect.minBodyLen.
func jsonNoiseServer(jsonBody string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jsonBody))
	}))
}

// TestScan_MatchBodyJSONKeepsOnlyMatching verifies that, without a match filter,
// the JSON noise responses appear, and that requiring a JSON field value the
// noise does NOT carry drops them all.
func TestScan_MatchBodyJSONKeepsOnlyMatching(t *testing.T) {
	srv := jsonNoiseServer(`{"ok":false,"error":"file not found","content":null}`)
	defer srv.Close()

	// Baseline: no match filter — the noise should show up.
	baseline := captureStdout(t, func() {
		if err := runScan(matchBodyJSONNoiseFlags(t, srv.URL, nil)); err != nil {
			t.Fatalf("runScan baseline: %v", err)
		}
	})
	if !strings.Contains(baseline, "[responded]") {
		t.Fatalf("baseline produced no [responded] lines:\n%s", baseline)
	}

	// Require ok:true — the noise (ok:false) is dropped.
	out := captureStdout(t, func() {
		if err := runScan(matchBodyJSONNoiseFlags(t, srv.URL, []string{"ok: true"})); err != nil {
			t.Fatalf("runScan filtered: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--match-body-json 'ok: true' should drop ok:false noise, got:\n%s", out)
	}
}

// TestScan_MatchBodyJSONKeepsMatchingResponses verifies that naming the noise's
// own JSON field value keeps the unconfirmed responses (the positive gate
// passes).
func TestScan_MatchBodyJSONKeepsMatchingResponses(t *testing.T) {
	srv := jsonNoiseServer(`{"ok":false,"error":"file not found"}`)
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(matchBodyJSONNoiseFlags(t, srv.URL, []string{"error: not found"})); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("--match-body-json 'error: not found' should keep the matching noise, got:\n%s", out)
	}
}

// TestScan_MatchBodyJSONNonJSONDrops verifies a body that is not valid JSON is
// dropped by an active matcher.
func TestScan_MatchBodyJSONNonJSONDrops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(noiseBody)) // plain text, not JSON
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(matchBodyJSONNoiseFlags(t, srv.URL, []string{"ok: true"})); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a non-JSON body must be dropped by an active --match-body-json gate, got:\n%s", out)
	}
}

// TestScan_MatchBodyJSONNestedAndConjunction verifies dot-path descent and that
// multiple rules compose as a conjunction: kept only if BOTH rules match.
func TestScan_MatchBodyJSONNestedAndConjunction(t *testing.T) {
	// Noise satisfies the first rule but not the second.
	srv := jsonNoiseServer(`{"ok":true,"data":{"path":"/var/log/app.log"}}`)
	defer srv.Close()

	rules := []string{"ok: true", "data.path: ^/etc/"}
	out := captureStdout(t, func() {
		if err := runScan(matchBodyJSONNoiseFlags(t, srv.URL, rules)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a response failing one conjunction rule must be dropped, got:\n%s", out)
	}

	// Now both rules match.
	srv2 := jsonNoiseServer(`{"ok":true,"data":{"path":"/etc/passwd"}}`)
	defer srv2.Close()
	out2 := captureStdout(t, func() {
		if err := runScan(matchBodyJSONNoiseFlags(t, srv2.URL, rules)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out2, "[responded]") {
		t.Fatalf("both rules satisfied should keep the response, got:\n%s", out2)
	}
}

// TestScan_MatchBodyJSONNeverDropsHits verifies a confirmed hit is reported even
// when --match-body-json names a value the hit's response does NOT carry. The
// leaked passwd file is content-confirmed and must survive the match gate, which
// only governs the unconfirmed stream.
func TestScan_MatchBodyJSONNeverDropsHits(t *testing.T) {
	const passwdBody = "root:x:0:0:root:/root:/bin/bash\n" // matches the fixture 'passwd' confirm
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "passwd") {
			_, _ = w.Write([]byte(passwdBody)) // a genuine read (not JSON)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":false,"error":"nope"}`))
	}))
	defer srv.Close()

	// Require ok:true — neither response carries it; this drops the noise AND
	// would drop the hit if the gate touched confirmed hits — it must not.
	out := captureStdout(t, func() {
		if err := runScan(matchBodyJSONNoiseFlags(t, srv.URL, []string{"ok: true"})); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[CONFIRMED]") {
		t.Fatalf("confirmed hit must survive --match-body-json, got:\n%s", out)
	}
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--match-body-json should drop every unconfirmed line, got:\n%s", out)
	}
}

// TestScan_MatchBodyJSONComposesWithMatchCode verifies the positive match gates
// are a conjunction across families: an unconfirmed response is kept only if BOTH
// its JSON matches AND its status is allowlisted. Here the JSON matches but the
// code does not, so the response is dropped.
func TestScan_MatchBodyJSONComposesWithMatchCode(t *testing.T) {
	srv := jsonNoiseServer(`{"ok":true}`) // 200, ok:true
	defer srv.Close()

	f := matchBodyJSONNoiseFlags(t, srv.URL, []string{"ok: true"}) // JSON gate passes
	f.matchCode = "500"                                            // status gate fails (noise is 200)
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a response failing the code gate must be dropped even when the JSON gate passes, got:\n%s", out)
	}
}

// TestScan_MatchBodyJSONComposesWithFilterRegex verifies the match gate runs
// before the suppression filters: --match-body-json keeps the matching JSON, then
// --filter-regex prunes it back out by raw body content.
func TestScan_MatchBodyJSONComposesWithFilterRegex(t *testing.T) {
	srv := jsonNoiseServer(`{"ok":true,"note":"soft-404"}`)
	defer srv.Close()

	f := matchBodyJSONNoiseFlags(t, srv.URL, []string{"ok: true"}) // keep: JSON matches
	f.filterRegex = "soft-404"                                     // then suppress: raw body matches the noise regex
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a kept response that also matches --filter-regex must be suppressed, got:\n%s", out)
	}
}

// TestScan_MatchBodyJSONInvalidSpecErrors verifies a malformed --match-body-json
// value fails before any requests fire.
func TestScan_MatchBodyJSONInvalidSpecErrors(t *testing.T) {
	srv := jsonNoiseServer(`{"ok":true}`)
	defer srv.Close()

	err := runScan(matchBodyJSONNoiseFlags(t, srv.URL, []string{"ok: ["})) // unparsable regex
	if err == nil {
		t.Fatal("expected error for malformed --match-body-json regex")
	}
	if !strings.Contains(err.Error(), "matchbodyjson") {
		t.Fatalf("unexpected error: %v", err)
	}
}
