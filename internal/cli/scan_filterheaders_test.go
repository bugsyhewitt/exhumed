package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// filterHeadersNoiseFlags builds scanFlags against the curated fixture DB that DO
// emit unconfirmed responses (onlyHits=false), so --filter-headers is the only
// thing that can suppress the "[responded]" stream. Chaining is disabled for
// determinism. The other suppression filters and the match gates are left empty
// so the negative header gate is exercised in isolation.
func filterHeadersNoiseFlags(t *testing.T, serverURL string, filterHeaders []string) scanFlags {
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
		filterHeaders:  filterHeaders,
	}
}

// TestScan_FilterHeadersSuppressesNoise verifies that, without a filter, the
// noise responses appear, and that naming a header value the noise DOES carry
// drops them all — the negative twin of --match-headers.
func TestScan_FilterHeadersSuppressesNoise(t *testing.T) {
	srv := headerNoiseServer("text/html; charset=utf-8", "")
	defer srv.Close()

	// Baseline: no filter — the noise should show up.
	baseline := captureStdout(t, func() {
		if err := runScan(filterHeadersNoiseFlags(t, srv.URL, nil)); err != nil {
			t.Fatalf("runScan baseline: %v", err)
		}
	})
	if !strings.Contains(baseline, "[responded]") {
		t.Fatalf("baseline produced no [responded] lines:\n%s", baseline)
	}

	// Name the Content-Type the noise DOES carry — every response is suppressed.
	out := captureStdout(t, func() {
		if err := runScan(filterHeadersNoiseFlags(t, srv.URL, []string{"Content-Type: text/html"})); err != nil {
			t.Fatalf("runScan filtered: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--filter-headers 'Content-Type: text/html' should drop text/html noise, got:\n%s", out)
	}
}

// TestScan_FilterHeadersKeepsNonMatching verifies that naming a header value the
// noise does NOT carry keeps the unconfirmed responses (the filter does not fire).
func TestScan_FilterHeadersKeepsNonMatching(t *testing.T) {
	srv := headerNoiseServer("text/html; charset=utf-8", "")
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(filterHeadersNoiseFlags(t, srv.URL, []string{"Content-Type: text/plain"})); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("--filter-headers 'Content-Type: text/plain' should NOT drop text/html noise, got:\n%s", out)
	}
}

// TestScan_FilterHeadersAbsentHeaderKeeps verifies that naming a header the
// response does not carry at all keeps every unconfirmed line — an absent header
// can never satisfy a noise rule.
func TestScan_FilterHeadersAbsentHeaderKeeps(t *testing.T) {
	srv := headerNoiseServer("text/html", "") // no X-Cache
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(filterHeadersNoiseFlags(t, srv.URL, []string{"X-Cache: HIT"})); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("naming an absent header should keep all noise, got:\n%s", out)
	}
}

// TestScan_FilterHeadersDisjunction verifies multiple --filter-headers rules
// compose as a disjunction: an unconfirmed response is suppressed if ANY rule
// matches, the deliberate opposite of --match-headers's conjunction. Here only
// the X-Powered-By rule matches, but that is enough to drop the response.
func TestScan_FilterHeadersDisjunction(t *testing.T) {
	srv := headerNoiseServer("text/html", "PHP/8.2") // Content-Type text/html, X-Powered-By PHP/8.2
	defer srv.Close()

	rules := []string{
		"Content-Type: text/plain", // does NOT match (noise is text/html)
		"X-Powered-By: PHP",        // matches — disjunction fires
	}
	out := captureStdout(t, func() {
		if err := runScan(filterHeadersNoiseFlags(t, srv.URL, rules)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a response matching one rule of the disjunction must be dropped, got:\n%s", out)
	}

	// Now neither rule matches — the response survives.
	srv2 := headerNoiseServer("application/json", "nginx")
	defer srv2.Close()
	out2 := captureStdout(t, func() {
		if err := runScan(filterHeadersNoiseFlags(t, srv2.URL, rules)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out2, "[responded]") {
		t.Fatalf("no rule satisfied should keep the response, got:\n%s", out2)
	}
}

// TestScan_FilterHeadersNeverDropsHits verifies a confirmed hit is reported even
// when --filter-headers names a header value the hit's response DOES carry. The
// leaked passwd file is content-confirmed and must survive the suppression gate,
// which only governs the unconfirmed stream.
func TestScan_FilterHeadersNeverDropsHits(t *testing.T) {
	const passwdBody = "root:x:0:0:root:/root:/bin/bash\n" // matches the fixture 'passwd' confirm
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html") // a value the noise rule names
		if strings.Contains(r.URL.RawQuery, "passwd") {
			_, _ = w.Write([]byte(passwdBody)) // a genuine read, 200
			return
		}
		_, _ = w.Write([]byte(noiseBody))
	}))
	defer srv.Close()

	// Name the Content-Type both responses carry: this drops the noise AND would
	// drop the hit if the gate touched confirmed hits — it must not.
	out := captureStdout(t, func() {
		if err := runScan(filterHeadersNoiseFlags(t, srv.URL, []string{"Content-Type: text/html"})); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[CONFIRMED]") {
		t.Fatalf("confirmed hit must survive --filter-headers, got:\n%s", out)
	}
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--filter-headers should drop every unconfirmed line, got:\n%s", out)
	}
}

// TestScan_FilterHeadersComposesWithMatchHeaders verifies the match gate runs
// before the suppression filters: --match-headers keeps the matching header
// block, then --filter-headers prunes it back out by a different header rule.
func TestScan_FilterHeadersComposesWithMatchHeaders(t *testing.T) {
	srv := headerNoiseServer("text/html", "PHP/8.2")
	defer srv.Close()

	f := filterHeadersNoiseFlags(t, srv.URL, []string{"X-Powered-By: PHP"}) // suppress: header matches
	f.matchHeaders = []string{"Content-Type: text/html"}                    // keep: header matches first
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a kept response that also matches --filter-headers must be suppressed, got:\n%s", out)
	}
}

// TestScan_FilterHeadersInvalidSpecErrors verifies a malformed --filter-headers
// value fails before any requests fire.
func TestScan_FilterHeadersInvalidSpecErrors(t *testing.T) {
	srv := headerNoiseServer("text/html", "")
	defer srv.Close()

	err := runScan(filterHeadersNoiseFlags(t, srv.URL, []string{"Content-Type: ["})) // unparsable regex
	if err == nil {
		t.Fatal("expected error for malformed --filter-headers regex")
	}
	if !strings.Contains(err.Error(), "headerfilter") {
		t.Fatalf("unexpected error: %v", err)
	}
}
