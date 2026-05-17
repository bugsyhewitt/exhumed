package detect_test

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bugsyhewitt/exhumed/internal/db"
	"github.com/bugsyhewitt/exhumed/internal/detect"
	"github.com/bugsyhewitt/exhumed/internal/engine"
)

// makeEntry builds a minimal CompiledEntry for testing.
func makeEntry(confirmType db.ConfirmType, patterns []string, negate []string, minMatches int) db.CompiledEntry {
	e := db.CompiledEntry{
		Entry: db.Entry{
			ID:        "test-entry",
			Name:      "Test Entry",
			Path:      "/test/file",
			OS:        []string{"linux"},
			InfoGoal:  db.InfoGoalSystemInfo,
			Privilege: db.PrivilegeAny,
			Confirm: db.Confirm{
				Type:       confirmType,
				Patterns:   patterns,
				Negate:     negate,
				MinMatches: minMatches,
			},
		},
	}
	if confirmType == db.ConfirmTypeRegex {
		e.CompiledPatterns = make([]*regexp.Regexp, len(patterns))
		for i, p := range patterns {
			e.CompiledPatterns[i] = regexp.MustCompile(p)
		}
		e.CompiledNegate = make([]*regexp.Regexp, len(negate))
		for i, p := range negate {
			e.CompiledNegate[i] = regexp.MustCompile(p)
		}
	}
	return e
}

func makeResult(status int, body string) engine.Result {
	return engine.Result{
		StatusCode: status,
		Body:       []byte(body),
		Headers:    make(map[string][]string),
		Elapsed:    time.Millisecond,
	}
}

// ── Regex confirm ─────────────────────────────────────────────────────────────

func TestDetect_RegexHit(t *testing.T) {
	entry := makeEntry(db.ConfirmTypeRegex, []string{`root:.*:0:0:`}, nil, 0)
	result := makeResult(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
	d := detect.Check(entry, result)
	if !d.Hit {
		t.Errorf("expected hit, got miss; snippets=%v", d.Snippets)
	}
}

func TestDetect_RegexMiss(t *testing.T) {
	entry := makeEntry(db.ConfirmTypeRegex, []string{`root:.*:0:0:`}, nil, 0)
	result := makeResult(200, "404 Not Found - the file was not found")
	d := detect.Check(entry, result)
	if d.Hit {
		t.Errorf("expected miss, got hit")
	}
}

func TestDetect_RegexMinMatches(t *testing.T) {
	// Requires 2 of 3 patterns to match; only 1 matches → miss.
	entry := makeEntry(db.ConfirmTypeRegex, []string{`root:`, `shadow:`, `nobody:`}, nil, 2)
	result := makeResult(200, "root:x:0:0:")
	d := detect.Check(entry, result)
	if d.Hit {
		t.Errorf("expected miss with only 1 of 2 required, got hit")
	}
}

func TestDetect_RegexMinMatchesSatisfied(t *testing.T) {
	entry := makeEntry(db.ConfirmTypeRegex, []string{`root:`, `daemon:`}, nil, 2)
	result := makeResult(200, "root:x:0:0:root\ndaemon:x:1:1:")
	d := detect.Check(entry, result)
	if !d.Hit {
		t.Errorf("expected hit with 2 of 2 required, got miss")
	}
}

// ── Keyword confirm ───────────────────────────────────────────────────────────

func TestDetect_KeywordHit(t *testing.T) {
	entry := makeEntry(db.ConfirmTypeKeyword, []string{"nameserver"}, nil, 0)
	result := makeResult(200, "# DNS\nnameserver 8.8.8.8\nnameserver 1.1.1.1")
	d := detect.Check(entry, result)
	if !d.Hit {
		t.Errorf("expected keyword hit")
	}
}

func TestDetect_KeywordCaseInsensitive(t *testing.T) {
	entry := makeEntry(db.ConfirmTypeKeyword, []string{"NAMESERVER"}, nil, 0)
	result := makeResult(200, "nameserver 8.8.8.8")
	d := detect.Check(entry, result)
	if !d.Hit {
		t.Errorf("expected case-insensitive keyword hit")
	}
}

func TestDetect_KeywordMiss(t *testing.T) {
	entry := makeEntry(db.ConfirmTypeKeyword, []string{"PRIVATE KEY"}, nil, 0)
	result := makeResult(200, "no keys here at all")
	d := detect.Check(entry, result)
	if d.Hit {
		t.Errorf("expected miss")
	}
}

// ── keyword-all confirm ───────────────────────────────────────────────────────

func TestDetect_KeywordAll_AllPresent(t *testing.T) {
	entry := makeEntry(db.ConfirmTypeKeywordAll, []string{"APP_KEY=", "DB_PASSWORD="}, nil, 0)
	result := makeResult(200, "APP_KEY=base64stuff\nDB_PASSWORD=secret")
	d := detect.Check(entry, result)
	if !d.Hit {
		t.Errorf("expected hit when all keywords present")
	}
}

func TestDetect_KeywordAll_OneMissing(t *testing.T) {
	entry := makeEntry(db.ConfirmTypeKeywordAll, []string{"APP_KEY=", "DB_PASSWORD="}, nil, 0)
	result := makeResult(200, "APP_KEY=base64stuff only this one")
	d := detect.Check(entry, result)
	if d.Hit {
		t.Errorf("expected miss when one keyword absent")
	}
}

// ── Negate ────────────────────────────────────────────────────────────────────

func TestDetect_NegateSuppress(t *testing.T) {
	entry := makeEntry(db.ConfirmTypeRegex, []string{`root:.*:0:0:`}, []string{`(?i)file not found`}, 0)
	// Body matches positive pattern but also matches negate → should NOT be a hit.
	result := makeResult(200, "root:x:0:0: file not found error")
	d := detect.Check(entry, result)
	if d.Hit {
		t.Errorf("expected negate to suppress hit")
	}
}

func TestDetect_NegateNoMatch(t *testing.T) {
	entry := makeEntry(db.ConfirmTypeRegex, []string{`root:.*:0:0:`}, []string{`(?i)file not found`}, 0)
	result := makeResult(200, "root:x:0:0:root:/root:/bin/bash")
	d := detect.Check(entry, result)
	if !d.Hit {
		t.Errorf("expected hit when negate does not match")
	}
}

// ── Status code and body edge cases ──────────────────────────────────────────

func TestDetect_Non200StatusNeverHit(t *testing.T) {
	entry := makeEntry(db.ConfirmTypeRegex, []string{`root:.*:0:0:`}, nil, 0)
	// Even with matching body content, non-2xx should not be a hit.
	result := makeResult(404, "root:x:0:0:root:/root:/bin/bash")
	d := detect.Check(entry, result)
	if d.Hit {
		t.Errorf("expected non-2xx status to prevent hit")
	}
}

func TestDetect_Non200Status500(t *testing.T) {
	entry := makeEntry(db.ConfirmTypeKeyword, []string{"nameserver"}, nil, 0)
	result := makeResult(500, "nameserver 8.8.8.8")
	d := detect.Check(entry, result)
	if d.Hit {
		t.Errorf("expected 500 status to prevent hit")
	}
}

func TestDetect_200IsHit(t *testing.T) {
	entry := makeEntry(db.ConfirmTypeKeyword, []string{"nameserver"}, nil, 0)
	result := makeResult(200, "nameserver 8.8.8.8")
	d := detect.Check(entry, result)
	if !d.Hit {
		t.Errorf("expected 200 + match to be a hit")
	}
}

func TestDetect_EmptyBodyNeverHit(t *testing.T) {
	entry := makeEntry(db.ConfirmTypeRegex, []string{`.`}, nil, 0)
	result := makeResult(200, "")
	d := detect.Check(entry, result)
	if d.Hit {
		t.Errorf("expected empty body to never be a hit")
	}
}

func TestDetect_ShortBodyNeverHit(t *testing.T) {
	entry := makeEntry(db.ConfirmTypeRegex, []string{`.`}, nil, 0)
	result := makeResult(200, "ab") // very short
	d := detect.Check(entry, result)
	if d.Hit {
		t.Errorf("expected very short body (<minBodyLen) to not be a hit")
	}
}

// ── Body cap ──────────────────────────────────────────────────────────────────

func TestDetect_BodyCapLimitsScanning(t *testing.T) {
	// Build a body larger than the cap. The pattern only appears after the cap.
	// The detector should NOT find it (because it caps scanning).
	cap := detect.MaxScanBytes
	body := strings.Repeat("x", cap+100) + "PRIVATE KEY"
	entry := makeEntry(db.ConfirmTypeKeyword, []string{"PRIVATE KEY"}, nil, 0)
	result := makeResult(200, body)
	d := detect.Check(entry, result)
	if d.Hit {
		t.Errorf("expected body cap to prevent matching content past %d bytes", cap)
	}
}

// ── Detection struct fields ───────────────────────────────────────────────────

func TestDetect_MatchedPatternsPopulated(t *testing.T) {
	entry := makeEntry(db.ConfirmTypeRegex, []string{`root:`, `daemon:`}, nil, 0)
	result := makeResult(200, "root:x:0:0:\ndaemon:x:1:1:")
	d := detect.Check(entry, result)
	if !d.Hit {
		t.Fatal("expected hit")
	}
	if len(d.MatchedPatterns) == 0 {
		t.Error("expected MatchedPatterns to be populated")
	}
}

func TestDetect_SnippetsPresent(t *testing.T) {
	entry := makeEntry(db.ConfirmTypeRegex, []string{`root:.*:0:0:`}, nil, 0)
	result := makeResult(200, "root:x:0:0:root:/root:/bin/bash")
	d := detect.Check(entry, result)
	if !d.Hit {
		t.Fatal("expected hit")
	}
	if len(d.Snippets) == 0 {
		t.Error("expected at least one snippet")
	}
}
