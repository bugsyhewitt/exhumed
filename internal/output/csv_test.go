package output

import (
	"bytes"
	"encoding/csv"
	"testing"
	"time"

	"github.com/bugsyhewitt/exhumed/internal/extract"
)

// TestParseFormatCSV verifies "csv" resolves to FormatCSV (the text/json cases
// are covered elsewhere; this pins the new third format).
func TestParseFormatCSV(t *testing.T) {
	got, err := ParseFormat("csv")
	if err != nil {
		t.Fatalf("ParseFormat(\"csv\"): unexpected error: %v", err)
	}
	if got != FormatCSV {
		t.Fatalf("ParseFormat(\"csv\") = %q, want %q", got, FormatCSV)
	}
}

// renderCSV drives a CSVWriter through one AddHit and returns the parsed records
// (including the header row).
func renderCSV(t *testing.T, findings []extract.Finding, showSecrets bool) [][]string {
	t.Helper()
	w := NewCSVWriter("http://target.local/?file=FUZZ", time.Unix(0, 0))
	w.AddHit("etc-passwd", "/etc/passwd", "dotdot-slash", 200, 12*time.Millisecond,
		[]string{"root:x:0:0"}, findings, showSecrets, 0)
	var buf bytes.Buffer
	if err := w.Finalise(&buf, 1, 0); err != nil {
		t.Fatalf("Finalise: %v", err)
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("parsing CSV output: %v\n%s", err, buf.String())
	}
	return recs
}

// TestCSVWriter_HeaderAndOneRowPerFinding verifies the header is emitted first
// and each finding becomes its own row carrying the shared hit columns.
func TestCSVWriter_HeaderAndOneRowPerFinding(t *testing.T) {
	findings := []extract.Finding{
		{Type: extract.FindingTypeUser, Key: "root", Value: "root:x:0:0", Source: "/etc/passwd", Confidence: 0.9},
		{Type: extract.FindingTypeUser, Key: "daemon", Value: "daemon:x:1:1", Source: "/etc/passwd", Confidence: 0.9},
	}
	recs := renderCSV(t, findings, true)

	if len(recs) != 3 { // header + 2 findings
		t.Fatalf("want 3 rows (header + 2 findings), got %d: %v", len(recs), recs)
	}
	if got, want := recs[0], csvHeader; len(got) != len(want) || got[0] != "entry_id" || got[len(got)-1] != "finding_depth" {
		t.Fatalf("header row mismatch: got %v", got)
	}
	// Shared hit columns must repeat on every finding row.
	for _, row := range recs[1:] {
		if row[0] != "etc-passwd" || row[1] != "/etc/passwd" || row[2] != "dotdot-slash" || row[3] != "200" {
			t.Fatalf("finding row lost its hit columns: %v", row)
		}
	}
	if recs[1][8] != "root" || recs[2][8] != "daemon" { // finding_key column index
		t.Fatalf("finding_key not carried per row: %v / %v", recs[1], recs[2])
	}
}

// TestCSVWriter_FindinglessHitEmitsOneRow verifies a confirmed hit with no
// extracted findings still produces exactly one row (blank finding columns), so
// every confirmed read appears in the CSV.
func TestCSVWriter_FindinglessHitEmitsOneRow(t *testing.T) {
	recs := renderCSV(t, nil, true)
	if len(recs) != 2 { // header + 1 finding-less row
		t.Fatalf("want 2 rows (header + 1 hit), got %d: %v", len(recs), recs)
	}
	row := recs[1]
	if row[1] != "/etc/passwd" {
		t.Fatalf("hit path missing on finding-less row: %v", row)
	}
	// finding columns (index 7..13) must all be blank.
	for i := 7; i < len(row); i++ {
		if row[i] != "" {
			t.Fatalf("finding column %d should be blank on a finding-less hit, got %q", i, row[i])
		}
	}
}

// TestCSVWriter_RedactionHonoursShowSecrets verifies a redacted finding is masked
// when showSecrets is false and printed in full when it is true — matching the
// JSON writer's contract so a CSV export never leaks what a JSON export masks.
func TestCSVWriter_RedactionHonoursShowSecrets(t *testing.T) {
	secret := []extract.Finding{
		{Type: extract.FindingTypeSecret, Key: "DB_PASSWORD", Value: "hunter2", Redacted: true, Source: "/proc/self/environ", Confidence: 0.85},
	}

	masked := renderCSV(t, secret, false)
	if masked[1][9] != "***REDACTED***" { // finding_value column index
		t.Fatalf("redacted secret must be masked when showSecrets=false, got %q", masked[1][9])
	}
	if masked[1][10] != "true" { // redacted column index
		t.Fatalf("redacted column should be true, got %q", masked[1][10])
	}

	shown := renderCSV(t, secret, true)
	if shown[1][9] != "hunter2" {
		t.Fatalf("secret must be shown in full when showSecrets=true, got %q", shown[1][9])
	}
	if shown[1][10] != "false" {
		t.Fatalf("redacted column should be false when shown, got %q", shown[1][10])
	}
}
