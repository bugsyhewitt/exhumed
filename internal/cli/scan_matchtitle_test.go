package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// matchTitleNoiseFlags builds scanFlags against the curated fixture DB that DO
// emit unconfirmed responses (onlyHits=false), so --match-title is the only
// thing governing the "[responded]" stream. Chaining is disabled for
// determinism. The suppression filters and the other match gates are left
// empty so the positive title gate is exercised in isolation.
func matchTitleNoiseFlags(t *testing.T, serverURL string, matchTitle []string) scanFlags {
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
		matchTitle:     matchTitle,
	}
}

// titleNoiseServer returns a body whose <title> is the supplied value for
// every miss, simulating an app whose "file not found" page carries a
// constant title (the soft-404 signature this filter is designed to discard
// when the operator names a different real-read title).
func titleNoiseServer(title string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><title>" + title + "</title></head><body>" + noiseBody + "</body></html>"))
	}))
}

// TestScan_MatchTitleKeepsOnlyMatching verifies that, without a match filter,
// the noise responses appear, and that naming a title the noise does NOT
// carry drops them all — only matching titles survive.
func TestScan_MatchTitleKeepsOnlyMatching(t *testing.T) {
	srv := titleNoiseServer("404 Not Found")
	defer srv.Close()

	// Baseline: no match filter — the noise should show up.
	baseline := captureStdout(t, func() {
		if err := runScan(matchTitleNoiseFlags(t, srv.URL, nil)); err != nil {
			t.Fatalf("runScan baseline: %v", err)
		}
	})
	if !strings.Contains(baseline, "[responded]") {
		t.Fatalf("baseline produced no [responded] lines:\n%s", baseline)
	}

	// Require a title the noise does NOT have — every response is dropped.
	out := captureStdout(t, func() {
		if err := runScan(matchTitleNoiseFlags(t, srv.URL, []string{"(?i)index of"})); err != nil {
			t.Fatalf("runScan filtered: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--match-title '(?i)index of' should drop '404 Not Found' noise, got:\n%s", out)
	}
}

// TestScan_MatchTitleKeepsMatchingResponses verifies that naming the noise's
// own title keeps the unconfirmed responses (the positive gate passes).
func TestScan_MatchTitleKeepsMatchingResponses(t *testing.T) {
	srv := titleNoiseServer("Index of /etc")
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(matchTitleNoiseFlags(t, srv.URL, []string{"(?i)index of"})); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("--match-title '(?i)index of' should keep matching noise, got:\n%s", out)
	}
}

// TestScan_MatchTitleAbsentTitleDrops verifies that requiring a title when
// the response has no <title> element at all drops every unconfirmed line.
func TestScan_MatchTitleAbsentTitleDrops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>" + noiseBody + "</body></html>")) // no <title>
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(matchTitleNoiseFlags(t, srv.URL, []string{"anything"})); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("requiring a title on a titleless body should drop all noise, got:\n%s", out)
	}
}

// TestScan_MatchTitleConjunction verifies multiple --match-title rules
// compose as a conjunction: an unconfirmed response is kept only if BOTH
// regexes match the same extracted title.
func TestScan_MatchTitleConjunction(t *testing.T) {
	srv := titleNoiseServer("Index of /home") // matches '(?i)index of' but not '/etc'
	defer srv.Close()

	rules := []string{
		"(?i)index of", // passes
		"/etc",         // fails
	}
	out := captureStdout(t, func() {
		if err := runScan(matchTitleNoiseFlags(t, srv.URL, rules)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a response failing one rule of the conjunction must be dropped, got:\n%s", out)
	}

	// Now both rules match — the response is kept.
	srv2 := titleNoiseServer("Index of /etc")
	defer srv2.Close()
	out2 := captureStdout(t, func() {
		if err := runScan(matchTitleNoiseFlags(t, srv2.URL, rules)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out2, "[responded]") {
		t.Fatalf("both rules satisfied should keep the response, got:\n%s", out2)
	}
}

// TestScan_MatchTitleNeverDropsHits verifies a confirmed hit is reported
// even when --match-title names a title the hit's response does NOT carry.
// The leaked passwd file is content-confirmed and must survive the match
// gate, which only governs the unconfirmed stream.
func TestScan_MatchTitleNeverDropsHits(t *testing.T) {
	const passwdBody = "root:x:0:0:root:/root:/bin/bash\n" // matches the fixture 'passwd' confirm
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if strings.Contains(r.URL.RawQuery, "passwd") {
			// A genuine read — no <title> at all, so the title gate would
			// drop it if it touched confirmed hits. It must not.
			_, _ = w.Write([]byte(passwdBody))
			return
		}
		_, _ = w.Write([]byte("<html><head><title>404 Not Found</title></head><body>" + noiseBody + "</body></html>"))
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(matchTitleNoiseFlags(t, srv.URL, []string{"(?i)index of"})); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[CONFIRMED]") {
		t.Fatalf("confirmed hit must survive --match-title, got:\n%s", out)
	}
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--match-title should drop every unconfirmed line, got:\n%s", out)
	}
}

// TestScan_MatchTitleComposesWithMatchCode verifies the positive match gates
// are a conjunction across families: an unconfirmed response is kept only if
// BOTH its title matches AND its status is allowlisted. Here the title
// matches but the code does not, so the response is dropped.
func TestScan_MatchTitleComposesWithMatchCode(t *testing.T) {
	srv := titleNoiseServer("Index of /etc") // 200, title matches
	defer srv.Close()

	f := matchTitleNoiseFlags(t, srv.URL, []string{"(?i)index of"}) // title gate passes
	f.matchCode = "500"                                             // status gate fails (noise is 200)
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a response failing the code gate must be dropped even when the title gate passes, got:\n%s", out)
	}
}

// TestScan_MatchTitleComposesWithFilterRegex verifies the match gate runs
// before the suppression filters: --match-title keeps the matching title,
// then --filter-regex prunes it back out by body content.
func TestScan_MatchTitleComposesWithFilterRegex(t *testing.T) {
	srv := titleNoiseServer("Index of /etc")
	defer srv.Close()

	f := matchTitleNoiseFlags(t, srv.URL, []string{"(?i)index of"}) // keep: title matches
	f.filterRegex = "soft-404"                                      // then suppress: body matches the noise regex
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a kept response that also matches --filter-regex must be suppressed, got:\n%s", out)
	}
}

// TestScan_MatchTitleInvalidSpecErrors verifies a malformed --match-title
// value fails before any requests fire.
func TestScan_MatchTitleInvalidSpecErrors(t *testing.T) {
	srv := titleNoiseServer("anything")
	defer srv.Close()

	err := runScan(matchTitleNoiseFlags(t, srv.URL, []string{"["})) // unparsable regex
	if err == nil {
		t.Fatal("expected error for malformed --match-title regex")
	}
	if !strings.Contains(err.Error(), "matchtitle") {
		t.Fatalf("unexpected error: %v", err)
	}
}
