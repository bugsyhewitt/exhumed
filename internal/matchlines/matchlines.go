// Package matchlines parses a response line-count "require" spec and decides
// whether a given response body should be KEPT (reported) because its line
// count matches an allowlist.
//
// matchlines is the positive complement to linefilter: where linefilter's
// --filter-lines SUPPRESSES unconfirmed "[responded]" responses whose body
// line count matches a known-noise count, matchlines' --match-lines inverts the
// polarity — it KEEPS only the unconfirmed responses whose line count matches
// an interesting count and drops everything else. This is the classic ffuf
// "-ml" (match lines) workflow, the positive twin of ffuf's "-fl", and the
// line-count sibling of matchsize's --match-size, matchwords's --match-words,
// matchcode's --match-code, matchtime's --match-time, and matchfilter's
// --match-regex. It completes the positive match family so every suppression
// filter has a mirror keep-gate.
//
// During LFI reconnaissance the traversal payloads against a single parameter
// overwhelmingly return one uniform soft-404 / WAF block page. Byte-size
// matching (--match-size) is the obvious tool, but it is brittle when an error
// template embeds a varying token — a request ID, a timestamp, a CSRF nonce —
// because the body length wobbles per request. Word-count matching
// (--match-words) recovers the case where the varying fragment is a single
// word, but some templates inject a *multi-word* varying fragment on a fixed
// line (an echoed query string, a "Request: GET /…" line, a stack-frame
// summary), so the word count also wobbles while the *line count* stays
// constant. --match-lines lets the operator name the distinctive line count(s)
// where leaked file content lands and drop the dynamic-length, dynamic-word
// noise that neither --match-size nor --match-words can pin — the inverse of
// naming the noise with --filter-lines.
//
// The gates compose naturally with the rest of the family. During
// reconnaissance an operator first narrows the haystack with the positive match
// gates (--match-regex, --match-code, --match-size, --match-time,
// --match-words, --match-lines), then prunes residual noise from the kept set
// with the --filter-* suppressors. The gating order in the scan loop is: a
// confirmed hit is ALWAYS reported; an unconfirmed response is reported only if
// (every match gate is satisfied) AND none of the suppression filters fire.
//
// This NEVER touches confirmed hits. Confirmation in exhumed is content-based
// (see internal/detect): a body that satisfies an entry's confirm block is a
// hit regardless of how many lines it contains. matchlines only governs the
// unconfirmed "[responded]" stream, turning it from "every body that responded"
// into "only the line counts worth a second look."
//
// Line count is defined exactly as ffuf defines it and as linefilter.CountLines
// computes it: the number of newline ('\n') terminators in the body. A body
// with N newlines has N lines by this definition. Consequences, all intentional
// and matching ffuf:
//
//	""                       -> 0 lines (empty body)
//	"one line, no newline"   -> 0 lines (no terminator)
//	"a\n"                    -> 1 line
//	"a\nb\n"                 -> 2 lines
//	"a\nb"                   -> 1 line (the trailing "b" has no terminator)
//
// "\r\n" is counted as a single line because only the '\n' is counted, which is
// the right behaviour for HTTP bodies that use CRLF.
//
// Spec grammar (the value of --match-lines), comma-separated terms:
//
//	0            keep bodies with zero lines
//	42           keep bodies with exactly 42 lines
//	10-20        keep the inclusive range [10, 20] lines
//	0,42,10-20   any combination
//
// Whitespace around terms is tolerated. An empty spec yields a Filter that
// keeps everything (Active() == false), so the scan output is unchanged.
//
// Line counts are non-negative. Negative terms, non-numeric terms, and reversed
// ranges are rejected at parse time so the operator learns immediately rather
// than silently keeping nothing.
package matchlines

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bugsyhewitt/exhumed/internal/linefilter"
)

// lineRange is an inclusive [lo, hi] line-count range. An exact count N is
// stored as the range [N, N].
type lineRange struct {
	lo int
	hi int
}

// Filter decides whether a response body of a given line count should be kept
// (reported) because it matches a require-lines allowlist. The zero value is
// inactive (keeps everything) and is safe to use.
type Filter struct {
	ranges []lineRange
}

// Parse builds a Filter from a comma-separated line-count allowlist spec. An
// empty (or all-whitespace) spec returns an inactive Filter and no error —
// callers treat an inactive filter as "keep everything." Malformed terms —
// non-numeric, negative, or reversed ranges — return an error so the operator
// learns immediately rather than silently keeping nothing.
func Parse(spec string) (*Filter, error) {
	f := &Filter{}
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return f, nil
	}

	for _, raw := range strings.Split(spec, ",") {
		term := strings.TrimSpace(raw)
		if term == "" {
			// A trailing or doubled comma is tolerated rather than fatal.
			continue
		}

		if lo, hi, ok := strings.Cut(term, "-"); ok {
			loN, err := parseNonNeg(strings.TrimSpace(lo))
			if err != nil {
				return nil, fmt.Errorf("matchlines: invalid range low bound in %q: %w", term, err)
			}
			hiN, err := parseNonNeg(strings.TrimSpace(hi))
			if err != nil {
				return nil, fmt.Errorf("matchlines: invalid range high bound in %q: %w", term, err)
			}
			if hiN < loN {
				return nil, fmt.Errorf("matchlines: reversed range %q: high (%d) < low (%d)", term, hiN, loN)
			}
			f.ranges = append(f.ranges, lineRange{lo: loN, hi: hiN})
			continue
		}

		n, err := parseNonNeg(term)
		if err != nil {
			return nil, fmt.Errorf("matchlines: invalid line count %q: %w", term, err)
		}
		f.ranges = append(f.ranges, lineRange{lo: n, hi: n})
	}

	return f, nil
}

// parseNonNeg parses a non-negative decimal integer line count.
func parseNonNeg(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("not an integer")
	}
	if n < 0 {
		return 0, fmt.Errorf("negative line count %d", n)
	}
	return n, nil
}

// Active reports whether the filter has any terms. When false, Keep always
// returns true (keep everything) and callers can skip the check entirely.
func (f *Filter) Active() bool {
	return f != nil && len(f.ranges) > 0
}

// Keep reports whether a response body of the given line count should be kept
// (reported) because it matches the allowlist. An inactive filter keeps
// everything, returning true. A negative count is never kept by an active
// filter.
func (f *Filter) Keep(lines int) bool {
	if !f.Active() {
		return true
	}
	if lines < 0 {
		return false
	}
	for _, r := range f.ranges {
		if lines >= r.lo && lines <= r.hi {
			return true
		}
	}
	return false
}

// KeepBody is a convenience wrapper that counts the lines in body using the
// exact same definition the filter compares against (linefilter.CountLines) and
// reports whether the body should be kept. Equivalent to
// f.Keep(linefilter.CountLines(body)).
func (f *Filter) KeepBody(body []byte) bool {
	if !f.Active() {
		return true
	}
	return f.Keep(linefilter.CountLines(body))
}
