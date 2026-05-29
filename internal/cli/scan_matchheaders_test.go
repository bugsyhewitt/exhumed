package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// matchHeadersNoiseFlags builds scanFlags against the curated fixture DB that DO
// emit unconfirmed responses (onlyHits=false), so --match-headers is the only
// thing governing the "[responded]" stream. Chaining is disabled for
// determinism. The suppression filters and the other match gates are left empty
// so the positive header gate is exercised in isolation.
func matchHeadersNoiseFlags(t *testing.T, serverURL string, matchHeaders []string) scanFlags {
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
		matchHeaders:   matchHeaders,
	}
}

// headerNoiseServer returns the fixed noiseBody for every miss but stamps a
// chosen Content-Type and X-Powered-By header, simulating an app whose "file not
// found" page carries a distinctive header block.
func headerNoiseServer(contentType, poweredBy string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		if poweredBy != "" {
			w.Header().Set("X-Powered-By", poweredBy)
		}
		_, _ = w.Write([]byte(noiseBody))
	}))
}

// TestScan_MatchHeadersKeepsOnlyMatching verifies that, without a match filter,
// the noise responses appear, and that naming a header value the noise does NOT
// carry drops them all — only matching header blocks survive.
func TestScan_MatchHeadersKeepsOnlyMatching(t *testing.T) {
	srv := headerNoiseServer("text/html; charset=utf-8", "")
	defer srv.Close()

	// Baseline: no match filter — the noise should show up.
	baseline := captureStdout(t, func() {
		if err := runScan(matchHeadersNoiseFlags(t, srv.URL, nil)); err != nil {
			t.Fatalf("runScan baseline: %v", err)
		}
	})
	if !strings.Contains(baseline, "[responded]") {
		t.Fatalf("baseline produced no [responded] lines:\n%s", baseline)
	}

	// Require a Content-Type the noise does NOT have — every response is dropped.
	out := captureStdout(t, func() {
		if err := runScan(matchHeadersNoiseFlags(t, srv.URL, []string{"Content-Type: text/plain"})); err != nil {
			t.Fatalf("runScan filtered: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--match-headers 'Content-Type: text/plain' should drop text/html noise, got:\n%s", out)
	}
}

// TestScan_MatchHeadersKeepsMatchingResponses verifies that naming the noise's
// own header value keeps the unconfirmed responses (the positive gate passes).
func TestScan_MatchHeadersKeepsMatchingResponses(t *testing.T) {
	srv := headerNoiseServer("text/html; charset=utf-8", "")
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(matchHeadersNoiseFlags(t, srv.URL, []string{"Content-Type: text/html"})); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("--match-headers 'Content-Type: text/html' should keep the noise, got:\n%s", out)
	}
}

// TestScan_MatchHeadersAbsentHeaderDrops verifies that requiring a header the
// response does not carry at all drops every unconfirmed line.
func TestScan_MatchHeadersAbsentHeaderDrops(t *testing.T) {
	srv := headerNoiseServer("text/html", "") // no X-Powered-By
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(matchHeadersNoiseFlags(t, srv.URL, []string{"X-Powered-By: PHP"})); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("requiring an absent header should drop all noise, got:\n%s", out)
	}
}

// TestScan_MatchHeadersConjunction verifies multiple --match-headers rules
// compose as a conjunction: an unconfirmed response is kept only if BOTH header
// rules match. Here the Content-Type matches but X-Powered-By does not, so the
// response is dropped.
func TestScan_MatchHeadersConjunction(t *testing.T) {
	srv := headerNoiseServer("text/plain", "nginx") // X-Powered-By is "nginx", not PHP
	defer srv.Close()

	rules := []string{
		"Content-Type: text/plain", // passes
		"X-Powered-By: PHP",        // fails
	}
	out := captureStdout(t, func() {
		if err := runScan(matchHeadersNoiseFlags(t, srv.URL, rules)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a response failing one rule of the conjunction must be dropped, got:\n%s", out)
	}

	// Now both rules match — the response is kept.
	srv2 := headerNoiseServer("text/plain", "PHP/8.2")
	defer srv2.Close()
	out2 := captureStdout(t, func() {
		if err := runScan(matchHeadersNoiseFlags(t, srv2.URL, rules)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out2, "[responded]") {
		t.Fatalf("both rules satisfied should keep the response, got:\n%s", out2)
	}
}

// TestScan_MatchHeadersNeverDropsHits verifies a confirmed hit is reported even
// when --match-headers names a header value the hit's response does NOT carry.
// The leaked passwd file is content-confirmed and must survive the match gate,
// which only governs the unconfirmed stream.
func TestScan_MatchHeadersNeverDropsHits(t *testing.T) {
	const passwdBody = "root:x:0:0:root:/root:/bin/bash\n" // matches the fixture 'passwd' confirm
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html") // a value the require rule rejects
		if strings.Contains(r.URL.RawQuery, "passwd") {
			_, _ = w.Write([]byte(passwdBody)) // a genuine read, 200
			return
		}
		_, _ = w.Write([]byte(noiseBody))
	}))
	defer srv.Close()

	// Require a Content-Type neither response carries: this drops the noise AND
	// would drop the hit if the gate touched confirmed hits — it must not.
	out := captureStdout(t, func() {
		if err := runScan(matchHeadersNoiseFlags(t, srv.URL, []string{"Content-Type: text/plain"})); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[CONFIRMED]") {
		t.Fatalf("confirmed hit must survive --match-headers, got:\n%s", out)
	}
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--match-headers should drop every unconfirmed line, got:\n%s", out)
	}
}

// TestScan_MatchHeadersComposesWithMatchCode verifies the positive match gates
// are a conjunction across families: an unconfirmed response is kept only if BOTH
// its headers match AND its status is allowlisted. Here the header matches but
// the code does not, so the response is dropped.
func TestScan_MatchHeadersComposesWithMatchCode(t *testing.T) {
	srv := headerNoiseServer("text/html", "") // 200, Content-Type text/html
	defer srv.Close()

	f := matchHeadersNoiseFlags(t, srv.URL, []string{"Content-Type: text/html"}) // header gate passes
	f.matchCode = "500"                                                          // status gate fails (noise is 200)
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a response failing the code gate must be dropped even when the header gate passes, got:\n%s", out)
	}
}

// TestScan_MatchHeadersComposesWithFilterRegex verifies the match gate runs
// before the suppression filters: --match-headers keeps the matching header
// block, then --filter-regex prunes it back out by body content.
func TestScan_MatchHeadersComposesWithFilterRegex(t *testing.T) {
	srv := headerNoiseServer("text/html", "")
	defer srv.Close()

	f := matchHeadersNoiseFlags(t, srv.URL, []string{"Content-Type: text/html"}) // keep: header matches
	f.filterRegex = "soft-404"                                                   // then suppress: body matches the noise regex
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a kept response that also matches --filter-regex must be suppressed, got:\n%s", out)
	}
}

// TestScan_MatchHeadersInvalidSpecErrors verifies a malformed --match-headers
// value fails before any requests fire.
func TestScan_MatchHeadersInvalidSpecErrors(t *testing.T) {
	srv := headerNoiseServer("text/html", "")
	defer srv.Close()

	err := runScan(matchHeadersNoiseFlags(t, srv.URL, []string{"Content-Type: ["})) // unparsable regex
	if err == nil {
		t.Fatal("expected error for malformed --match-headers regex")
	}
	if !strings.Contains(err.Error(), "matchheaders") {
		t.Fatalf("unexpected error: %v", err)
	}
}
