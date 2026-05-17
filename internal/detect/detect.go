// Package detect confirms whether an HTTP response body actually contains the
// target file, using the entry's confirm block. It is the difference between
// "got a 200" and "actually read the file."
package detect

import (
	"strings"

	"github.com/bugsyhewitt/exhumed/internal/db"
	"github.com/bugsyhewitt/exhumed/internal/engine"
)

// MaxScanBytes is the maximum number of body bytes the detector scans.
// Bodies longer than this are truncated before pattern matching to bound
// both memory use and ReDoS exposure.
const MaxScanBytes = 1 << 20 // 1 MiB

// minBodyLen is the minimum number of bytes a body must have to be considered
// as a potential hit. Responses shorter than this are almost certainly error
// pages or empty responses, not real file contents.
const minBodyLen = 4

// Detection is the result of running the detector against one HTTP response.
type Detection struct {
	// Hit is true when the confirm block is satisfied and the entry was
	// actually read (not just a 200 with an error page).
	Hit bool
	// MatchedPatterns lists the confirm patterns (by index) that matched.
	MatchedPatterns []int
	// Snippets holds short excerpts surrounding each match, capped for output.
	Snippets []string
	// Confidence is a short human-readable note explaining the verdict.
	Confidence string
}

// Check runs the confirm block of entry against the HTTP result and returns a
// Detection. It is safe to call concurrently. It never recompiles regexes;
// those are in entry.CompiledPatterns from the loader.
func Check(entry db.CompiledEntry, result engine.Result) Detection {
	// Non-2xx status codes are never hits.
	if result.StatusCode < 200 || result.StatusCode >= 300 {
		return Detection{Confidence: "non-2xx status"}
	}

	// Empty or trivially short bodies are never hits.
	if len(result.Body) < minBodyLen {
		return Detection{Confidence: "body too short"}
	}

	// Cap the body scan window.
	body := result.Body
	if len(body) > MaxScanBytes {
		body = body[:MaxScanBytes]
	}

	confirm := entry.Entry.Confirm

	switch confirm.Type {
	case db.ConfirmTypeRegex:
		return checkRegex(entry, body)
	case db.ConfirmTypeKeyword:
		return checkKeyword(confirm, body, false)
	case db.ConfirmTypeKeywordAll:
		return checkKeyword(confirm, body, true)
	default:
		return Detection{Confidence: "unknown confirm type"}
	}
}

// checkRegex handles type:regex confirm blocks.
func checkRegex(entry db.CompiledEntry, body []byte) Detection {
	confirm := entry.Entry.Confirm
	bodyStr := string(body)

	// Check negate patterns first. Any negate match → not a hit.
	for _, re := range entry.CompiledNegate {
		if re.MatchString(bodyStr) {
			return Detection{Confidence: "negate pattern matched"}
		}
	}

	need := confirm.EffectiveMinMatches()
	var matchedIdx []int
	var snippets []string

	for i, re := range entry.CompiledPatterns {
		loc := re.FindStringIndex(bodyStr)
		if loc == nil {
			continue
		}
		matchedIdx = append(matchedIdx, i)
		snippets = append(snippets, excerpt(bodyStr, loc[0], loc[1]))
	}

	if len(matchedIdx) >= need {
		return Detection{
			Hit:             true,
			MatchedPatterns: matchedIdx,
			Snippets:        snippets,
			Confidence:      "regex match",
		}
	}
	return Detection{
		Confidence: "regex: insufficient matches",
	}
}

// checkKeyword handles type:keyword and type:keyword-all confirm blocks.
func checkKeyword(confirm db.Confirm, body []byte, requireAll bool) Detection {
	bodyLower := strings.ToLower(string(body))
	var matchedIdx []int
	var snippets []string

	for i, pat := range confirm.Patterns {
		patLower := strings.ToLower(pat)
		idx := strings.Index(bodyLower, patLower)
		if idx >= 0 {
			matchedIdx = append(matchedIdx, i)
			snippets = append(snippets, excerpt(string(body), idx, idx+len(pat)))
		}
	}

	if requireAll {
		// keyword-all: every pattern must be present.
		if len(matchedIdx) == len(confirm.Patterns) {
			return Detection{
				Hit:             true,
				MatchedPatterns: matchedIdx,
				Snippets:        snippets,
				Confidence:      "keyword-all match",
			}
		}
		return Detection{Confidence: "keyword-all: not all patterns present"}
	}

	// keyword: at least EffectiveMinMatches() must match.
	need := confirm.EffectiveMinMatches()
	if len(matchedIdx) >= need {
		return Detection{
			Hit:             true,
			MatchedPatterns: matchedIdx,
			Snippets:        snippets,
			Confidence:      "keyword match",
		}
	}
	return Detection{Confidence: "keyword: insufficient matches"}
}

// excerpt returns a short string surrounding [start, end) in s, suitable for
// display. It is capped to avoid large output.
func excerpt(s string, start, end int) string {
	const window = 60
	lo := start - window
	if lo < 0 {
		lo = 0
	}
	hi := end + window
	if hi > len(s) {
		hi = len(s)
	}
	snip := s[lo:hi]
	// Replace control characters that would break terminal output.
	snip = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 && r != '\n' {
			return '.'
		}
		return r
	}, snip)
	if lo > 0 {
		snip = "…" + snip
	}
	if hi < len(s) {
		snip = snip + "…"
	}
	return snip
}
