package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// oobBaseFlags builds scanFlags pointing at the given server and collaborator
// domain, using the fixture database and a quiet, single-worker configuration.
func oobBaseFlags(serverURL, oobDomain string) scanFlags {
	return scanFlags{
		url:            serverURL + "/?file=FUZZ",
		marker:         "FUZZ",
		method:         "GET",
		concurrency:    2,
		timeout:        5 * time.Second,
		traversalDepth: 1,
		dbPath:         "", // filled in by callers that need curatedDBPath
		onlyHits:       true,
		maxDepth:       0,
		maxTargets:     0,
		outputFormat:   "text",
		oob:            oobDomain,
	}
}

// TestScan_OOBInvalidDomainErrors verifies that a malformed collaborator domain
// (one with a scheme, path, or missing TLD) fails before any request fires.
func TestScan_OOBInvalidDomainErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cases := []string{
		"http://collaborator.example.com", // has scheme
		"collaborator.example.com/path",   // has path
		"notadomain",                      // no TLD dot
		"",                                // empty — but empty disables OOB so this is fine; skip
	}
	for _, bad := range cases {
		if bad == "" {
			continue
		}
		t.Run(bad, func(t *testing.T) {
			f := oobBaseFlags(srv.URL, bad)
			f.dbPath = curatedDBPath(t)
			err := runScan(f)
			if err == nil {
				t.Fatalf("expected error for bad OOB domain %q, got nil", bad)
			}
			if !strings.Contains(err.Error(), "oob") {
				t.Fatalf("expected 'oob' in error for %q, got: %v", bad, err)
			}
		})
	}
}

// TestScan_OOBFiresExtraRequests verifies that when --oob is set, the scan fires
// additional requests (the OOB payloads) on top of the regular traversal set.
// We measure total HTTP requests to the test server: with OOB the count must be
// strictly greater than without OOB (assuming the same entry set).
func TestScan_OOBFiresExtraRequests(t *testing.T) {
	var noOOBReqs, withOOBReqs int64

	makeServer := func(counter *int64) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt64(counter, 1)
			w.WriteHeader(http.StatusNotFound)
		}))
	}

	// Run without OOB.
	srvNoOOB := makeServer(&noOOBReqs)
	defer srvNoOOB.Close()
	f := oobBaseFlags(srvNoOOB.URL, "")
	f.dbPath = curatedDBPath(t)
	if err := runScan(f); err != nil {
		t.Fatalf("runScan without --oob: %v", err)
	}

	// Run with OOB (valid but non-existent collaborator — requests just 404 back
	// to the test server since the marker substitution points at its own URL).
	srvWithOOB := makeServer(&withOOBReqs)
	defer srvWithOOB.Close()
	f2 := oobBaseFlags(srvWithOOB.URL, "oast.example.com")
	f2.dbPath = curatedDBPath(t)
	if err := runScan(f2); err != nil {
		t.Fatalf("runScan with --oob: %v", err)
	}

	no := atomic.LoadInt64(&noOOBReqs)
	with := atomic.LoadInt64(&withOOBReqs)
	if with <= no {
		t.Fatalf("--oob should fire more requests than without: without=%d with=%d", no, with)
	}
}

// TestScan_OOBDisabledByDefault verifies that omitting --oob does not add any
// OOB-summary line to the scan output.
func TestScan_OOBDisabledByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	f := oobBaseFlags(srv.URL, "")
	f.dbPath = curatedDBPath(t)
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "OOB payloads fired") {
		t.Fatalf("no OOB summary expected without --oob, got:\n%s", out)
	}
}

// TestScan_OOBSummaryReportsFiredCount verifies that when --oob is set and the
// scan completes, the text summary includes the "OOB payloads fired" line with
// a positive count and the collaborator domain.
func TestScan_OOBSummaryReportsFiredCount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	const domain = "oast.example.com"
	f := oobBaseFlags(srv.URL, domain)
	f.dbPath = curatedDBPath(t)
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "OOB payloads fired") {
		t.Fatalf("expected OOB summary line, got:\n%s", out)
	}
	if !strings.Contains(out, domain) {
		t.Fatalf("expected collaborator domain %q in OOB summary, got:\n%s", domain, out)
	}
}
