package output

import (
	"encoding/csv"
	"io"
	"strconv"
	"time"

	"github.com/bugsyhewitt/exhumed/internal/extract"
)

// csvHeader is the fixed column order for CSV output. Each row is one confirmed
// finding; a confirmed hit with no findings still emits a single row with the
// finding columns left blank, so every confirmed read appears in the output.
var csvHeader = []string{
	"entry_id",
	"path",
	"technique",
	"status_code",
	"elapsed_ms",
	"chain",
	"chain_depth",
	"finding_type",
	"finding_key",
	"finding_value",
	"redacted",
	"source",
	"confidence",
	"finding_depth",
}

// csvRow is one flattened (hit, finding) pair awaiting render. Holding rows
// until Finalise mirrors JSONWriter's collect-then-emit model, so a CSV scan
// and a JSON scan surface the identical confirmed-hit set.
type csvRow struct {
	hit     HitJSON
	finding *FindingJSON // nil when the hit produced no findings
}

// CSVWriter collects confirmed hits and renders them as CSV (one row per
// finding) on Finalise. It is the spreadsheet/grep-friendly companion to
// JSONWriter and shares its AddHit signature so the scan loop can drive either
// writer through the same call sites.
type CSVWriter struct {
	rows []csvRow
}

// NewCSVWriter creates an empty CSVWriter. The target/startedAt parameters mirror
// NewJSONWriter for call-site symmetry; CSV carries no document-level preamble,
// so they are intentionally unused.
func NewCSVWriter(_ string, _ time.Time) *CSVWriter {
	return &CSVWriter{}
}

// AddHit records a confirmed hit, flattening it into one row per finding (or a
// single finding-less row). Redaction honours showSecrets exactly as JSONWriter
// does, so a CSV export never leaks a secret a JSON export would have masked.
func (w *CSVWriter) AddHit(entryID, path, technique string, status int, elapsed time.Duration,
	snippets []string, findings []extract.Finding, showSecrets bool, chainDepth int) {
	h := newHitJSON(entryID, path, technique, status, elapsed, snippets, chainDepth)
	if len(findings) == 0 {
		w.rows = append(w.rows, csvRow{hit: h})
		return
	}
	for _, f := range findings {
		fj := findingToJSON(f, showSecrets)
		w.rows = append(w.rows, csvRow{hit: h, finding: &fj})
	}
}

// Finalise writes the header row followed by every collected finding row to out.
// The totalRequests/chainTargetsQueued parameters mirror JSONWriter.Finalise for
// call-site symmetry; CSV has no summary row, so they are intentionally unused.
func (w *CSVWriter) Finalise(out io.Writer, _ int, _ int) error {
	cw := csv.NewWriter(out)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, r := range w.rows {
		rec := []string{
			r.hit.EntryID,
			r.hit.Path,
			r.hit.Technique,
			strconv.Itoa(r.hit.StatusCode),
			strconv.FormatInt(r.hit.ElapsedMs, 10),
			strconv.FormatBool(r.hit.Chain),
			strconv.Itoa(r.hit.ChainDepth),
		}
		if r.finding != nil {
			rec = append(rec,
				r.finding.Type,
				r.finding.Key,
				r.finding.Value,
				strconv.FormatBool(r.finding.Redacted),
				r.finding.Source,
				strconv.FormatFloat(float64(r.finding.Confidence), 'g', -1, 32),
				strconv.Itoa(r.finding.Depth),
			)
		} else {
			rec = append(rec, "", "", "", "", "", "", "")
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
