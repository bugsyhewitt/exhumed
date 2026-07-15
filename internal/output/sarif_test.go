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

// sarifDoc mirrors the top-level SARIF document for unmarshalling in tests.
type sarifDoc struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Rules   []struct {
					ID               string `json:"id"`
					Name             string `json:"name"`
					ShortDescription struct {
						Text string `json:"text"`
					} `json:"shortDescription"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
		} `json:"results"`
	} `json:"runs"`
}

func parseSARIF(t *testing.T, b []byte) sarifDoc {
	t.Helper()
	var doc sarifDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("SARIF unmarshal: %v\n%s", err, b)
	}
	return doc
}

func TestSARIFWriter_EmptyResult(t *testing.T) {
	w := output.NewSARIFWriter("http://target.local/?file=FUZZ", time.Now())

	var buf bytes.Buffer
	if err := w.Finalise(&buf, 0, 0); err != nil {
		t.Fatalf("Finalise: %v", err)
	}

	doc := parseSARIF(t, buf.Bytes())

	if doc.Schema != "https://json.schemastore.org/sarif-2.1.0.json" {
		t.Errorf("$schema: got %q", doc.Schema)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version: got %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs: got %d, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "exhumed" {
		t.Errorf("driver.name: got %q", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) != 0 {
		t.Errorf("rules: got %d, want 0", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 0 {
		t.Errorf("results: got %d, want 0", len(run.Results))
	}
}

func TestSARIFWriter_SingleHit(t *testing.T) {
	w := output.NewSARIFWriter("http://target.local/?file=FUZZ", time.Now())
	w.AddHit("linux-os:passwd", "/etc/passwd", "dotdot-slash", 200,
		43*time.Millisecond, []string{"root:x:0"}, nil, false, 0)

	var buf bytes.Buffer
	if err := w.Finalise(&buf, 10, 0); err != nil {
		t.Fatalf("Finalise: %v", err)
	}

	doc := parseSARIF(t, buf.Bytes())
	run := doc.Runs[0]

	if len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("rules: got %d, want 1", len(run.Tool.Driver.Rules))
	}
	rule := run.Tool.Driver.Rules[0]
	if rule.ID != "LFI/linux-os:passwd" {
		t.Errorf("rule.id: got %q", rule.ID)
	}
	if rule.Name != "LfiLinuxOsPasswd" {
		t.Errorf("rule.name: got %q, want LfiLinuxOsPasswd", rule.Name)
	}

	if len(run.Results) != 1 {
		t.Fatalf("results: got %d, want 1", len(run.Results))
	}
	r := run.Results[0]
	if r.RuleID != "LFI/linux-os:passwd" {
		t.Errorf("result.ruleId: got %q", r.RuleID)
	}
	if r.Level != "error" {
		t.Errorf("result.level: got %q, want error", r.Level)
	}
	if !strings.Contains(r.Message.Text, "/etc/passwd") {
		t.Errorf("message: %q missing path", r.Message.Text)
	}
	if !strings.Contains(r.Message.Text, "dotdot-slash") {
		t.Errorf("message: %q missing technique", r.Message.Text)
	}
	if len(r.Locations) != 1 {
		t.Fatalf("locations: got %d, want 1", len(r.Locations))
	}
	if r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "http://target.local/?file=FUZZ" {
		t.Errorf("location.uri: got %q", r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	fp := r.PartialFingerprints["primaryLocationLineHash/v1"]
	if fp != "linux-os:passwd:dotdot-slash" {
		t.Errorf("fingerprint: got %q", fp)
	}
}

func TestSARIFWriter_RuleDeduplication(t *testing.T) {
	w := output.NewSARIFWriter("http://target.local/?x=FUZZ", time.Now())
	// Same entry_id, two different techniques — must produce ONE rule, two results.
	w.AddHit("linux-os:passwd", "/etc/passwd", "dotdot-slash", 200, time.Millisecond, nil, nil, false, 0)
	w.AddHit("linux-os:passwd", "/etc/passwd", "url-encoded", 200, time.Millisecond, nil, nil, false, 0)

	var buf bytes.Buffer
	if err := w.Finalise(&buf, 2, 0); err != nil {
		t.Fatalf("Finalise: %v", err)
	}

	doc := parseSARIF(t, buf.Bytes())
	run := doc.Runs[0]
	if len(run.Tool.Driver.Rules) != 1 {
		t.Errorf("rules: got %d, want 1 (deduplication failed)", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 2 {
		t.Errorf("results: got %d, want 2", len(run.Results))
	}
}

func TestSARIFWriter_MultipleEntries(t *testing.T) {
	w := output.NewSARIFWriter("http://target.local/?x=FUZZ", time.Now())
	w.AddHit("linux-os:passwd", "/etc/passwd", "dotdot-slash", 200, time.Millisecond, nil, nil, false, 0)
	w.AddHit("linux-proc:environ", "/proc/self/environ", "dotdot-slash", 200, time.Millisecond, nil, nil, false, 0)

	var buf bytes.Buffer
	if err := w.Finalise(&buf, 20, 3); err != nil {
		t.Fatalf("Finalise: %v", err)
	}

	doc := parseSARIF(t, buf.Bytes())
	run := doc.Runs[0]
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("rules: got %d, want 2", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 2 {
		t.Errorf("results: got %d, want 2", len(run.Results))
	}
}

func TestSARIFWriter_FindingsInMessage(t *testing.T) {
	findings := []extract.Finding{
		{Type: extract.FindingTypeSecret, Key: "DB_PASSWORD", Value: "secret", Redacted: true, Confidence: 0.9},
		{Type: extract.FindingTypeUser, Key: "root", Confidence: 0.95},
	}
	w := output.NewSARIFWriter("http://target.local/?x=FUZZ", time.Now())
	w.AddHit("app:config", "/etc/app.conf", "dotdot-slash", 200, 10*time.Millisecond,
		nil, findings, false, 0)

	var buf bytes.Buffer
	if err := w.Finalise(&buf, 1, 0); err != nil {
		t.Fatalf("Finalise: %v", err)
	}

	doc := parseSARIF(t, buf.Bytes())
	r := doc.Runs[0].Results[0]
	if !strings.Contains(r.Message.Text, "2 finding(s)") {
		t.Errorf("message: %q missing findings count", r.Message.Text)
	}
}

func TestSARIFWriter_ChainDepthInMessage(t *testing.T) {
	w := output.NewSARIFWriter("http://target.local/?x=FUZZ", time.Now())
	w.AddHit("chain:/root/.ssh/id_rsa", "/root/.ssh/id_rsa", "dotdot-slash", 200,
		5*time.Millisecond, nil, nil, false, 2)

	var buf bytes.Buffer
	if err := w.Finalise(&buf, 50, 0); err != nil {
		t.Fatalf("Finalise: %v", err)
	}

	doc := parseSARIF(t, buf.Bytes())
	r := doc.Runs[0].Results[0]
	if !strings.Contains(r.Message.Text, "chain depth 2") {
		t.Errorf("message: %q missing chain depth", r.Message.Text)
	}
}

func TestSARIFWriter_ValidJSON(t *testing.T) {
	w := output.NewSARIFWriter("http://example.com/?x=FUZZ", time.Now())
	w.AddHit("test", "/etc/passwd", "dotdot-slash", 200, time.Millisecond, nil, nil, false, 0)

	var buf bytes.Buffer
	if err := w.Finalise(&buf, 1, 0); err != nil {
		t.Fatalf("Finalise: %v", err)
	}

	if !json.Valid(buf.Bytes()) {
		t.Errorf("output is not valid JSON:\n%s", buf.String())
	}
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Errorf("JSON output does not end with newline")
	}
}

func TestParseFormat_SARIF(t *testing.T) {
	f, err := output.ParseFormat("sarif")
	if err != nil {
		t.Fatalf("ParseFormat(sarif): %v", err)
	}
	if f != output.FormatSARIF {
		t.Errorf("got %q, want FormatSARIF", f)
	}
}
