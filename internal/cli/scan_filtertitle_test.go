package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// filterTitleNoiseFlags builds scanFlags against the curated fixture DB that DO
// emit unconfirmed responses (onlyHits=false), so --filter-title is the only
// thing that can suppress the "[responded]" stream. Chaining is disabled for
// determinism. The other suppression filters and the match gates are left empty
// so the negative title gate is exercised in isolation.
func filterTitleNoiseFlags(t *testing.T, serverURL string, filterTitle []string) scanFlags {
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
		filterTitle:    filterTitle,
	}
}

// TestScan_FilterTitleSuppressesNoise verifies that, without a filter, the
// noise responses appear, and that naming the noise's own <title> drops them
// all — the negative twin of --match-title.
func TestScan_FilterTitleSuppressesNoise(t *testing.T) {
	srv := titleNoiseServer("404 Not Found")
	defer srv.Close()

	// Baseline: no filter — the noise should show up.
	baseline := captureStdout(t, func() {
		if err := runScan(filterTitleNoiseFlags(t, srv.URL, nil)); err != nil {
			t.Fatalf("runScan baseline: %v", err)
		}
	})
	if !strings.Contains(baseline, "[responded]") {
		t.Fatalf("baseline produced no [responded] lines:\n%s", baseline)
	}

	// Name the title the noise carries — every response is suppressed.
	out := captureStdout(t, func() {
		if err := runScan(filterTitleNoiseFlags(t, srv.URL, []string{"404 Not Found"})); err != nil {
			t.Fatalf("runScan filtered: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--filter-title '404 Not Found' should drop matching noise, got:\n%s", out)
	}
}

// TestScan_FilterTitleKeepsUnmatched verifies that naming a title the noise
// does NOT carry leaves the unconfirmed responses untouched — only matching
// titles are suppressed.
func TestScan_FilterTitleKeepsUnmatched(t *testing.T) {
	srv := titleNoiseServer("Index of /etc")
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(filterTitleNoiseFlags(t, srv.URL, []string{"404 Not Found"})); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("--filter-title '404 Not Found' should NOT drop 'Index of /etc' noise, got:\n%s", out)
	}
}

// TestScan_FilterTitleDisjunction verifies multiple --filter-title rules
// compose as a disjunction: an unconfirmed response is suppressed if ANY
// regex matches the extracted title.
func TestScan_FilterTitleDisjunction(t *testing.T) {
	rules := []string{
		`404 Not Found`,
		`(?i)access denied`,
	}

	// First rule fires.
	srv1 := titleNoiseServer("404 Not Found")
	defer srv1.Close()
	out1 := captureStdout(t, func() {
		if err := runScan(filterTitleNoiseFlags(t, srv1.URL, rules)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out1, "[responded]") {
		t.Fatalf("first rule should suppress, got:\n%s", out1)
	}

	// Second rule fires.
	srv2 := titleNoiseServer("Access Denied")
	defer srv2.Close()
	out2 := captureStdout(t, func() {
		if err := runScan(filterTitleNoiseFlags(t, srv2.URL, rules)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out2, "[responded]") {
		t.Fatalf("second rule should suppress, got:\n%s", out2)
	}

	// Neither rule fires.
	srv3 := titleNoiseServer("Welcome")
	defer srv3.Close()
	out3 := captureStdout(t, func() {
		if err := runScan(filterTitleNoiseFlags(t, srv3.URL, rules)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out3, "[responded]") {
		t.Fatalf("neither rule matches; should keep, got:\n%s", out3)
	}
}

// TestScan_FilterTitleNoTitleIsKept verifies a response whose body has no
// extractable <title> is NOT suppressed even when --filter-title is active —
// the suppressor cannot classify a titleless body as title-shaped noise.
func TestScan_FilterTitleNoTitleIsKept(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>" + noiseBody + "</body></html>")) // no <title>
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(filterTitleNoiseFlags(t, srv.URL, []string{"anything"})); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("a titleless body must not be suppressed by --filter-title, got:\n%s", out)
	}
}

// TestScan_FilterTitleNeverDropsHits verifies a confirmed hit is reported
// even when --filter-title names a regex that matches a title the hit's
// response would carry. Confirmation is content-based and must survive the
// suppression gate.
func TestScan_FilterTitleNeverDropsHits(t *testing.T) {
	const passwdBody = "root:x:0:0:root:/root:/bin/bash\n" // matches the fixture 'passwd' confirm
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if strings.Contains(r.URL.RawQuery, "passwd") {
			// A genuine read served inside the same '404 Not Found' chrome
			// the soft-404 uses — the filter would suppress it if it touched
			// confirmed hits. It must not.
			_, _ = w.Write([]byte("<html><head><title>404 Not Found</title></head><body>" + passwdBody + "</body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><head><title>404 Not Found</title></head><body>" + noiseBody + "</body></html>"))
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(filterTitleNoiseFlags(t, srv.URL, []string{"404 Not Found"})); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[CONFIRMED]") {
		t.Fatalf("confirmed hit must survive --filter-title, got:\n%s", out)
	}
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--filter-title should suppress every unconfirmed line, got:\n%s", out)
	}
}

// TestScan_FilterTitleComposesWithFilterCode verifies the suppression family
// composes as a disjunction across surfaces: a response is dropped if either
// --filter-title or --filter-code fires.
func TestScan_FilterTitleComposesWithFilterCode(t *testing.T) {
	srv := titleNoiseServer("Index of /etc") // 200, title doesn't match the noise spec
	defer srv.Close()

	// --filter-title alone does not suppress (title is "Index of /etc").
	f := filterTitleNoiseFlags(t, srv.URL, []string{"404 Not Found"})
	// --filter-code 200 suppresses the noise via status, even though the title
	// does not match — the suppression family is a disjunction.
	f.filterCode = "200"
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a response matched by --filter-code must be suppressed regardless of --filter-title, got:\n%s", out)
	}
}

// TestScan_FilterTitleComposesWithMatchTitle verifies the match gates run
// BEFORE the suppression filters: --match-title keeps the matching title,
// then --filter-title prunes it back out.
func TestScan_FilterTitleComposesWithMatchTitle(t *testing.T) {
	srv := titleNoiseServer("Index of /etc")
	defer srv.Close()

	f := filterTitleNoiseFlags(t, srv.URL, []string{"(?i)index of"}) // suppress: matches
	f.matchTitle = []string{"(?i)index of"}                          // keep: also matches
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a response kept by --match-title that also matches --filter-title must be suppressed, got:\n%s", out)
	}
}

// TestScan_FilterTitleInvalidSpecErrors verifies a malformed --filter-title
// value fails before any requests fire.
func TestScan_FilterTitleInvalidSpecErrors(t *testing.T) {
	srv := titleNoiseServer("anything")
	defer srv.Close()

	err := runScan(filterTitleNoiseFlags(t, srv.URL, []string{"["})) // unparsable regex
	if err == nil {
		t.Fatal("expected error for malformed --filter-title regex")
	}
	if !strings.Contains(err.Error(), "filtertitle") {
		t.Fatalf("unexpected error: %v", err)
	}
}
