package cli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// matchSizeNoiseFlags builds scanFlags against the curated fixture DB that DO
// emit unconfirmed responses (onlyHits=false), so --match-size is the only thing
// governing the "[responded]" stream. Chaining is disabled for determinism. The
// suppression filters and the other match gates are left empty so the positive
// size gate is exercised in isolation.
func matchSizeNoiseFlags(t *testing.T, serverURL, matchSize string) scanFlags {
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
		matchSize:      matchSize,
	}
}

// TestScan_MatchSizeKeepsOnlyAllowlisted verifies that, without a match filter,
// the uniform-size noise responses appear, and that naming a size the noise does
// NOT carry drops them all — only allowlisted body lengths survive.
func TestScan_MatchSizeKeepsOnlyAllowlisted(t *testing.T) {
	srv := noiseServer() // every miss answers a fixed-length noiseBody
	defer srv.Close()

	// Baseline: no match filter — the noise should show up.
	baseline := captureStdout(t, func() {
		if err := runScan(matchSizeNoiseFlags(t, srv.URL, "")); err != nil {
			t.Fatalf("runScan baseline: %v", err)
		}
	})
	if !strings.Contains(baseline, "[responded]") {
		t.Fatalf("baseline produced no [responded] lines:\n%s", baseline)
	}

	// Match only a size the noise does NOT have — the noise is dropped because
	// its length is not in the allowlist (the inverse of --filter-size).
	out := captureStdout(t, func() {
		if err := runScan(matchSizeNoiseFlags(t, srv.URL, "9999")); err != nil {
			t.Fatalf("runScan filtered: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--match-size 9999 should drop all %d-byte noise, got:\n%s", len(noiseBody), out)
	}
}

// TestScan_MatchSizeKeepsMatchingNoise verifies that naming the noise's own body
// length in --match-size keeps the unconfirmed responses (the positive gate
// passes).
func TestScan_MatchSizeKeepsMatchingNoise(t *testing.T) {
	srv := noiseServer()
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(matchSizeNoiseFlags(t, srv.URL, fmt.Sprintf("%d", len(noiseBody)))); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("--match-size %d should keep the noise responses, got:\n%s", len(noiseBody), out)
	}
}

// TestScan_MatchSizeRangeKeeps verifies a range spec keeps a body length that
// falls inside it (the 27-byte noise inside 20-40).
func TestScan_MatchSizeRangeKeeps(t *testing.T) {
	srv := noiseServer()
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(matchSizeNoiseFlags(t, srv.URL, "20-40")); err != nil { // 27 ∈ [20,40]
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("range match 20-40 should keep a 27-byte body, got:\n%s", out)
	}
}

// TestScan_MatchSizeNeverDropsHits verifies a confirmed hit is reported even
// when --match-size names a length the hit's response body does NOT carry. The
// leaked passwd file is content-confirmed and must survive the match gate, which
// only governs the unconfirmed stream.
func TestScan_MatchSizeNeverDropsHits(t *testing.T) {
	const passwdBody = "root:x:0:0:root:/root:/bin/bash\n" // matches the fixture 'passwd' confirm
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "passwd") {
			_, _ = w.Write([]byte(passwdBody)) // a genuine read, 200
			return
		}
		_, _ = w.Write([]byte(noiseBody)) // uniform-size noise
	}))
	defer srv.Close()

	// Match only a size neither body has: this drops the noise AND would drop the
	// hit if the gate touched confirmed hits — it must not.
	out := captureStdout(t, func() {
		if err := runScan(matchSizeNoiseFlags(t, srv.URL, "1")); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[CONFIRMED]") {
		t.Fatalf("confirmed hit must survive --match-size, got:\n%s", out)
	}
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--match-size 1 should drop every unconfirmed line, got:\n%s", out)
	}
}

// TestScan_MatchSizeComposesWithMatchCode verifies the positive match gates are
// a conjunction: an unconfirmed response is kept only if BOTH its body length is
// allowlisted AND its status is allowlisted. Here the size matches but the code
// does not, so the response is dropped.
func TestScan_MatchSizeComposesWithMatchCode(t *testing.T) {
	srv := noiseServer() // 200, body is noiseBody (27 bytes)
	defer srv.Close()

	f := matchSizeNoiseFlags(t, srv.URL, fmt.Sprintf("%d", len(noiseBody))) // size gate passes
	f.matchCode = "500"                                                     // status gate fails (noise is 200)
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a response failing the code gate must be dropped even when the size gate passes, got:\n%s", out)
	}
}

// TestScan_MatchSizeComposesWithFilterSize verifies the match gate runs before
// the suppression filters: --match-size keeps the allowlisted length, then
// --filter-size prunes it back out. With both naming the same size, the net
// result is suppression (the suppressor wins on the kept set).
func TestScan_MatchSizeComposesWithFilterSize(t *testing.T) {
	srv := noiseServer()
	defer srv.Close()

	f := matchSizeNoiseFlags(t, srv.URL, fmt.Sprintf("%d", len(noiseBody))) // keep: size matches
	f.filterSize = fmt.Sprintf("%d", len(noiseBody))                        // then suppress: size also matches the filter
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a kept response that also matches --filter-size must be suppressed, got:\n%s", out)
	}
}

// TestScan_MatchSizeInvalidSpecErrors verifies a malformed --match-size value
// fails before any requests fire.
func TestScan_MatchSizeInvalidSpecErrors(t *testing.T) {
	srv := noiseServer()
	defer srv.Close()

	err := runScan(matchSizeNoiseFlags(t, srv.URL, "200-100")) // reversed range
	if err == nil {
		t.Fatal("expected error for reversed --match-size range")
	}
	if !strings.Contains(err.Error(), "matchsize") {
		t.Fatalf("unexpected error: %v", err)
	}
}
