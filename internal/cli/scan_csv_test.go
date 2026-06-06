package cli

import (
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// csvScanFlags builds scanFlags driving the curated fixture DB with CSV output.
// Chaining is disabled and a single worker is used for determinism.
func csvScanFlags(t *testing.T, serverURL string) scanFlags {
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
		outputFormat:   "csv",
	}
}

// TestScan_CSVOutputEmitsConfirmedHitRow verifies that `--output csv` writes a
// header row followed by at least one confirmed-hit row for a leaked passwd, and
// that the CSV is well-formed (constant column count across rows).
func TestScan_CSVOutputEmitsConfirmedHitRow(t *testing.T) {
	const passwdBody = "root:x:0:0:root:/root:/bin/bash\n" // matches the fixture 'passwd' confirm
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "passwd") {
			_, _ = w.Write([]byte(passwdBody)) // genuine read, 200 -> confirmed hit
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(csvScanFlags(t, srv.URL)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})

	recs, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatalf("CSV output is not well-formed: %v\n%s", err, out)
	}
	if len(recs) < 2 {
		t.Fatalf("expected a header row plus at least one confirmed-hit row, got %d rows:\n%s", len(recs), out)
	}
	if recs[0][0] != "entry_id" || recs[0][1] != "path" {
		t.Fatalf("first row should be the CSV header, got: %v", recs[0])
	}

	var sawPasswd bool
	for _, row := range recs[1:] {
		if strings.Contains(row[1], "passwd") {
			sawPasswd = true
			if row[3] != "200" {
				t.Fatalf("confirmed passwd row should carry status 200, got: %v", row)
			}
		}
	}
	if !sawPasswd {
		t.Fatalf("expected a confirmed-hit row for /etc/passwd in CSV output:\n%s", out)
	}

	// Text-mode noise markers must not leak into structured CSV output.
	if strings.Contains(out, "── Scan complete") || strings.Contains(out, "[CONFIRMED]") {
		t.Fatalf("CSV output must not contain text-mode summary/markers:\n%s", out)
	}
}
