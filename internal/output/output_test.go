package output_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bugsyhewitt/exhumed/internal/extract"
	"github.com/bugsyhewitt/exhumed/internal/output"
)

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input   string
		want    output.Format
		wantErr bool
	}{
		{"text", output.FormatText, false},
		{"", output.FormatText, false},
		{"json", output.FormatJSON, false},
		{"xml", "", true},
		{"JSON", "", true},
	}
	for _, tc := range tests {
		got, err := output.ParseFormat(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseFormat(%q): expected error, got nil", tc.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseFormat(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseFormat(%q): got %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestJSONWriter_EmptyResult(t *testing.T) {
	start := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	w := output.NewJSONWriter("http://target.local/?file=FUZZ", start)

	var buf bytes.Buffer
	if err := w.Finalise(&buf, 100, 0); err != nil {
		t.Fatalf("Finalise: %v", err)
	}

	var result output.ScanResultJSON
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal: %v", err)
	}

	if result.SchemaVersion != "1" {
		t.Errorf("schema_version: got %q, want %q", result.SchemaVersion, "1")
	}
	if result.Target != "http://target.local/?file=FUZZ" {
		t.Errorf("target: got %q", result.Target)
	}
	if result.TotalRequests != 100 {
		t.Errorf("total_requests: got %d, want 100", result.TotalRequests)
	}
	if result.ConfirmedHits != 0 {
		t.Errorf("confirmed_hits: got %d, want 0", result.ConfirmedHits)
	}
	if len(result.Hits) != 0 {
		t.Errorf("hits: got %d items, want 0", len(result.Hits))
	}
	if result.StartedAt != "2026-05-26T12:00:00Z" {
		t.Errorf("started_at: got %q", result.StartedAt)
	}
}

func TestJSONWriter_HitWithFindings(t *testing.T) {
	start := time.Now()
	w := output.NewJSONWriter("http://target.local/?file=FUZZ", start)

	findings := []extract.Finding{
		{
			Type:       extract.FindingTypeSecret,
			Key:        "DB_PASSWORD",
			Value:      "super-secret-pw",
			Redacted:   true,
			Source:     "/etc/app.conf",
			Confidence: 0.9,
		},
		{
			Type:       extract.FindingTypeUser,
			Key:        "root",
			Value:      "",
			Redacted:   false,
			Source:     "/etc/passwd",
			Confidence: 0.95,
			Extra:      map[string]string{"home": "/root", "shell": "/bin/bash"},
		},
	}

	w.AddHit("linux-os:passwd", "/etc/passwd", "dotdot-slash", 200,
		50*time.Millisecond, []string{"root:x:0"}, findings, false, 0)

	var buf bytes.Buffer
	if err := w.Finalise(&buf, 42, 5); err != nil {
		t.Fatalf("Finalise: %v", err)
	}

	var result output.ScanResultJSON
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal: %v", err)
	}

	if result.ConfirmedHits != 1 {
		t.Fatalf("confirmed_hits: got %d, want 1", result.ConfirmedHits)
	}
	if result.ChainTargetsQueued != 5 {
		t.Errorf("chain_targets_queued: got %d, want 5", result.ChainTargetsQueued)
	}

	h := result.Hits[0]
	if h.EntryID != "linux-os:passwd" {
		t.Errorf("entry_id: got %q", h.EntryID)
	}
	if h.Technique != "dotdot-slash" {
		t.Errorf("technique: got %q", h.Technique)
	}
	if h.ElapsedMs != 50 {
		t.Errorf("elapsed_ms: got %d, want 50", h.ElapsedMs)
	}
	if h.Chain {
		t.Errorf("chain: expected false for depth-0 hit")
	}
	if len(h.Snippets) != 1 || h.Snippets[0] != "root:x:0" {
		t.Errorf("snippets: got %v", h.Snippets)
	}
	if len(h.Findings) != 2 {
		t.Fatalf("findings: got %d, want 2", len(h.Findings))
	}

	// Secret should be redacted when showSecrets=false.
	secretFinding := h.Findings[0]
	if secretFinding.Key != "DB_PASSWORD" {
		t.Errorf("finding[0].key: got %q", secretFinding.Key)
	}
	if secretFinding.Value != "***REDACTED***" {
		t.Errorf("finding[0].value: expected redaction, got %q", secretFinding.Value)
	}
	if !secretFinding.Redacted {
		t.Errorf("finding[0].redacted: expected true")
	}

	// Non-redacted finding should pass through.
	userFinding := h.Findings[1]
	if userFinding.Key != "root" {
		t.Errorf("finding[1].key: got %q", userFinding.Key)
	}
	if userFinding.Redacted {
		t.Errorf("finding[1].redacted: expected false")
	}
	if userFinding.Extra["home"] != "/root" {
		t.Errorf("finding[1].extra.home: got %q", userFinding.Extra["home"])
	}
}

func TestJSONWriter_ShowSecrets(t *testing.T) {
	w := output.NewJSONWriter("http://target.local/?file=FUZZ", time.Now())

	findings := []extract.Finding{
		{
			Type:       extract.FindingTypeSecret,
			Key:        "SECRET_KEY",
			Value:      "plaintext-value",
			Redacted:   true,
			Source:     "/etc/app.conf",
			Confidence: 0.8,
		},
	}

	// showSecrets=true — value must be plaintext.
	w.AddHit("app:config", "/etc/app.conf", "dotdot-slash", 200, 10*time.Millisecond,
		nil, findings, true, 0)

	var buf bytes.Buffer
	if err := w.Finalise(&buf, 10, 0); err != nil {
		t.Fatalf("Finalise: %v", err)
	}

	var result output.ScanResultJSON
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal: %v", err)
	}

	f := result.Hits[0].Findings[0]
	if f.Value != "plaintext-value" {
		t.Errorf("value: got %q, want plaintext-value", f.Value)
	}
	if f.Redacted {
		t.Errorf("redacted: expected false when show_secrets=true")
	}
}

func TestJSONWriter_ChainHit(t *testing.T) {
	w := output.NewJSONWriter("http://target.local/?file=FUZZ", time.Now())

	w.AddHit("chain:/root/.ssh/id_rsa", "/root/.ssh/id_rsa", "dotdot-slash", 200,
		20*time.Millisecond, nil, nil, false, 2)

	var buf bytes.Buffer
	if err := w.Finalise(&buf, 200, 10); err != nil {
		t.Fatalf("Finalise: %v", err)
	}

	var result output.ScanResultJSON
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal: %v", err)
	}

	h := result.Hits[0]
	if !h.Chain {
		t.Errorf("chain: expected true for depth-2 hit")
	}
	if h.ChainDepth != 2 {
		t.Errorf("chain_depth: got %d, want 2", h.ChainDepth)
	}
}

func TestJSONWriter_ValidJSON(t *testing.T) {
	w := output.NewJSONWriter("http://example.com/?x=FUZZ", time.Now())
	w.AddHit("test", "/etc/passwd", "dotdot-slash", 200, time.Millisecond,
		[]string{"root:x"}, nil, false, 0)

	var buf bytes.Buffer
	if err := w.Finalise(&buf, 1, 0); err != nil {
		t.Fatalf("Finalise: %v", err)
	}

	// Verify the output is valid JSON and well-formed.
	if !json.Valid(buf.Bytes()) {
		t.Errorf("output is not valid JSON:\n%s", buf.String())
	}

	// Verify it ends with a newline (json.Encoder guarantee).
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Errorf("JSON output does not end with newline")
	}
}
