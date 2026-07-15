// Package output provides structured output formatting for exhumed scan results.
// It supports four modes: text (human-readable, default), json (machine-readable),
// csv (spreadsheet/grep-friendly, one row per confirmed finding), and sarif
// (SARIF 2.1.0 for CI/code-scanning integration).
//
// JSON and CSV output are emitted as a single document written to stdout after the
// scan completes. Text output is written incrementally as hits are found.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/bugsyhewitt/exhumed/internal/extract"
)

// Format selects the output mode.
type Format string

const (
	// FormatText is the default human-readable output.
	FormatText Format = "text"
	// FormatJSON emits a single JSON document after the scan completes.
	FormatJSON Format = "json"
	// FormatCSV emits a CSV document (one row per confirmed finding) after the
	// scan completes.
	FormatCSV Format = "csv"
	// FormatSARIF emits a SARIF 2.1.0 JSON document after the scan completes,
	// suitable for ingestion by GitHub Code Scanning and other CI security tools.
	FormatSARIF Format = "sarif"
)

// ParseFormat parses a format string, returning an error on unrecognised values.
func ParseFormat(s string) (Format, error) {
	switch s {
	case "text", "":
		return FormatText, nil
	case "json":
		return FormatJSON, nil
	case "csv":
		return FormatCSV, nil
	case "sarif":
		return FormatSARIF, nil
	default:
		return "", fmt.Errorf("unknown output format %q: valid values are text, json, csv, sarif", s)
	}
}

// FindingJSON is the JSON representation of one extracted finding.
type FindingJSON struct {
	// Type classifies the finding (e.g. "secret", "user", "ssh-key").
	Type string `json:"type"`
	// Key is the finding label (key name, username, kind of secret).
	Key string `json:"key"`
	// Value is the extracted value. Redacted to "***REDACTED***" unless show_secrets is true.
	Value string `json:"value"`
	// Redacted indicates whether the value was masked.
	Redacted bool `json:"redacted"`
	// Source is the file path this finding came from.
	Source string `json:"source"`
	// Confidence is a 0–1 estimate of extraction accuracy.
	Confidence float32 `json:"confidence"`
	// Extra holds parser-specific metadata (e.g. home, shell for users).
	Extra map[string]string `json:"extra,omitempty"`
	// Depth is the follow-on chain generation (0 = initial scan).
	Depth int `json:"depth"`
}

// HitJSON is the JSON representation of one confirmed LFI hit.
type HitJSON struct {
	// EntryID is the database entry identifier.
	EntryID string `json:"entry_id"`
	// Path is the file path that was successfully read.
	Path string `json:"path"`
	// Technique is the traversal technique that worked (e.g. "dotdot-slash").
	Technique string `json:"technique"`
	// StatusCode is the HTTP response status.
	StatusCode int `json:"status_code"`
	// ElapsedMs is the round-trip time in milliseconds.
	ElapsedMs int64 `json:"elapsed_ms"`
	// Snippets are confirm-block matched excerpts from the response body.
	Snippets []string `json:"snippets,omitempty"`
	// Findings are the extracted intelligence items.
	Findings []FindingJSON `json:"findings,omitempty"`
	// Chain indicates this hit was produced by the follow-on chain engine.
	Chain bool `json:"chain"`
	// ChainDepth is the generation depth (0 = initial scan, >0 = chain hit).
	ChainDepth int `json:"chain_depth"`
}

// ScanResultJSON is the top-level JSON document emitted after a scan.
type ScanResultJSON struct {
	// SchemaVersion identifies the output format version for downstream parsers.
	SchemaVersion string `json:"schema_version"`
	// StartedAt is the scan start time (RFC3339).
	StartedAt string `json:"started_at"`
	// CompletedAt is the scan completion time (RFC3339).
	CompletedAt string `json:"completed_at"`
	// Target is the URL that was scanned.
	Target string `json:"target"`
	// TotalRequests is the number of HTTP requests fired.
	TotalRequests int `json:"total_requests"`
	// ConfirmedHits is the count of confirmed readable files.
	ConfirmedHits int `json:"confirmed_hits"`
	// ChainTargetsQueued is the number of follow-on paths generated.
	ChainTargetsQueued int `json:"chain_targets_queued"`
	// Hits contains every confirmed hit with its findings.
	Hits []HitJSON `json:"hits"`
}

// JSONWriter collects scan results and renders them as JSON.
type JSONWriter struct {
	result ScanResultJSON
}

// NewJSONWriter creates a JSONWriter initialised with scan metadata.
func NewJSONWriter(target string, startedAt time.Time) *JSONWriter {
	return &JSONWriter{
		result: ScanResultJSON{
			SchemaVersion: "1",
			StartedAt:     startedAt.UTC().Format(time.RFC3339),
			Target:        target,
			Hits:          []HitJSON{},
		},
	}
}

// AddHit records a confirmed hit.
func (w *JSONWriter) AddHit(entryID, path, technique string, status int, elapsed time.Duration,
	snippets []string, findings []extract.Finding, showSecrets bool, chainDepth int) {
	h := HitJSON{
		EntryID:    entryID,
		Path:       path,
		Technique:  technique,
		StatusCode: status,
		ElapsedMs:  elapsed.Milliseconds(),
		Snippets:   snippets,
		Chain:      chainDepth > 0,
		ChainDepth: chainDepth,
	}
	for _, f := range findings {
		val := f.Value
		redacted := false
		if f.Redacted && !showSecrets {
			val = "***REDACTED***"
			redacted = true
		}
		h.Findings = append(h.Findings, FindingJSON{
			Type:       string(f.Type),
			Key:        f.Key,
			Value:      val,
			Redacted:   redacted,
			Source:     f.Source,
			Confidence: f.Confidence,
			Extra:      f.Extra,
			Depth:      f.Depth,
		})
	}
	w.result.Hits = append(w.result.Hits, h)
}

// Finalise sets summary counters and writes the JSON document to w.
func (w *JSONWriter) Finalise(out io.Writer, totalRequests, chainTargetsQueued int) error {
	w.result.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	w.result.TotalRequests = totalRequests
	w.result.ConfirmedHits = len(w.result.Hits)
	w.result.ChainTargetsQueued = chainTargetsQueued

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(w.result)
}
