package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	"github.com/bugsyhewitt/exhumed/internal/extract"
	"github.com/bugsyhewitt/exhumed/internal/version"
)

// SARIF 2.1.0 structures — only the fields exhumed populates are modelled.
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

type sarifDocument struct {
	Schema  string    `json:"$schema"`
	Version string    `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	HelpURI          string         `json:"helpUri"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// sarifHitRecord holds a single confirmed hit awaiting SARIF serialisation.
type sarifHitRecord struct {
	entryID     string
	path        string
	technique   string
	status      int
	elapsed     time.Duration
	findings    []extract.Finding
	showSecrets bool
	chainDepth  int
}

// SARIFWriter collects confirmed hits and renders a SARIF 2.1.0 document on
// Finalise. It satisfies the same AddHit/Finalise contract as JSONWriter and
// CSVWriter so the scan loop can drive any writer through the same call sites.
type SARIFWriter struct {
	target string
	hits   []sarifHitRecord
}

// NewSARIFWriter creates an empty SARIFWriter. The startedAt parameter mirrors
// the other writers' signature for call-site symmetry; SARIF carries no
// document-level scan-start timestamp.
func NewSARIFWriter(target string, _ time.Time) *SARIFWriter {
	return &SARIFWriter{target: target}
}

// AddHit records a confirmed hit for later SARIF serialisation.
func (w *SARIFWriter) AddHit(entryID, path, technique string, status int, elapsed time.Duration,
	_ []string, findings []extract.Finding, showSecrets bool, chainDepth int) {
	w.hits = append(w.hits, sarifHitRecord{
		entryID:     entryID,
		path:        path,
		technique:   technique,
		status:      status,
		elapsed:     elapsed,
		findings:    findings,
		showSecrets: showSecrets,
		chainDepth:  chainDepth,
	})
}

// Finalise writes the SARIF 2.1.0 document to out. The totalRequests and
// chainTargetsQueued parameters mirror the other writers' signature for
// call-site symmetry; they are not included in the SARIF output.
func (w *SARIFWriter) Finalise(out io.Writer, _, _ int) error {
	rules := buildSARIFRules(w.hits)
	results := buildSARIFResults(w.target, w.hits)

	doc := sarifDocument{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "exhumed",
					Version:        version.Version,
					InformationURI: "https://github.com/bugsyhewitt/exhumed",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// buildSARIFRules produces a deduplicated rule list from the confirmed hits,
// one rule per unique entry ID.
func buildSARIFRules(hits []sarifHitRecord) []sarifRule {
	seen := map[string]bool{}
	rules := []sarifRule{}
	for _, h := range hits {
		rid := sarifRuleID(h.entryID)
		if seen[rid] {
			continue
		}
		seen[rid] = true
		rules = append(rules, sarifRule{
			ID:   rid,
			Name: sarifRuleName(h.entryID),
			ShortDescription: sarifMessage{
				Text: fmt.Sprintf("LFI: file readable via path traversal (%s)", h.path),
			},
			HelpURI: "https://github.com/bugsyhewitt/exhumed",
			Properties: map[string]any{
				"tags": []string{"security", "lfi", "path-traversal"},
			},
		})
	}
	return rules
}

// buildSARIFResults produces one SARIF result per confirmed hit.
func buildSARIFResults(target string, hits []sarifHitRecord) []sarifResult {
	results := []sarifResult{}
	for _, h := range hits {
		text := fmt.Sprintf("File readable via LFI: %s using technique %q (HTTP %d, %dms)",
			h.path, h.technique, h.status, h.elapsed.Milliseconds())
		if len(h.findings) > 0 {
			text += fmt.Sprintf("; %d finding(s) extracted", len(h.findings))
		}
		if h.chainDepth > 0 {
			text += fmt.Sprintf(" [chain depth %d]", h.chainDepth)
		}

		props := map[string]any{
			"technique":  h.technique,
			"entryId":    h.entryID,
			"chainDepth": h.chainDepth,
		}
		if len(h.findings) > 0 {
			types := make([]string, 0, len(h.findings))
			for _, f := range h.findings {
				types = append(types, string(f.Type))
			}
			props["findingTypes"] = types
		}

		results = append(results, sarifResult{
			RuleID:  sarifRuleID(h.entryID),
			Level:   "error",
			Message: sarifMessage{Text: text},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: target},
				},
			}},
			PartialFingerprints: map[string]string{
				"primaryLocationLineHash/v1": h.entryID + ":" + h.technique,
			},
			Properties: props,
		})
	}
	return results
}

// sarifRuleID converts an entry ID to a namespaced SARIF rule ID.
func sarifRuleID(entryID string) string {
	return "LFI/" + entryID
}

// sarifRuleName converts a kebab/colon/slash-delimited entry ID to a
// PascalCase rule name with an "Lfi" prefix (SARIF convention).
func sarifRuleName(entryID string) string {
	parts := strings.FieldsFunc(entryID, func(r rune) bool {
		return r == '-' || r == ':' || r == '/' || r == '_'
	})
	var sb strings.Builder
	sb.WriteString("Lfi")
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		rs := []rune(p)
		rs[0] = unicode.ToUpper(rs[0])
		sb.WriteString(string(rs))
	}
	return sb.String()
}
