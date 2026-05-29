// Package linefilter parses response line-count filter specs and decides
// whether a given response body should be suppressed from output based on the
// number of newline-separated lines it contains.
//
// During a scan, generic web apps return a soft-404 / WAF block page for every
// path that does not exist. Byte-size filtering (--filter-size) is the obvious
// tool for that noise, but it is brittle: many error templates embed a varying
// token — a request ID, a timestamp, a CSRF nonce, a cache buster — so the body
// length wobbles per request and a fixed --filter-size misses most of them.
// Word-count filtering (--filter-words) handles the case where the varying
// token is a single word. But some templates inject a *multi-word* varying
// fragment on a fixed line — an echoed query string, a "Request: GET /…" line,
// a stack-frame summary — so the word count also wobbles while the *line count*
// stays constant. Line-count filtering catches exactly that residual noise,
// which is why ffuf exposes "-fl" alongside "-fs" and "-fw".
//
// linefilter implements that classic ffuf "-fl" workflow, completing the
// noise-suppression set alongside --filter-size (respfilter), --filter-code
// (codefilter), --filter-regex (bodyfilter), --filter-time (timefilter), and
// --filter-words (wordfilter).
//
// This NEVER touches confirmed hits. Confirmation in exhumed is content-based
// (see internal/detect): a body that satisfies an entry's confirm block is a
// hit regardless of how many lines it contains. linefilter only quiets the
// unconfirmed "[responded]" stream — a finer-grained scalpel than --only-hits.
//
// Line count is defined as ffuf defines it: the number of newline ('\n')
// characters in the body. This counts line *terminators*, matching ffuf's
// "Lines" metric (a body with N newlines has N lines by this definition).
// Consequences of that definition, all intentional and matching ffuf:
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
// Spec grammar (the value of --filter-lines), comma-separated terms:
//
//	0            bodies with zero lines
//	42           bodies with exactly 42 lines
//	10-20        inclusive range [10, 20] lines
//	0,42,10-20   any combination
//
// Whitespace around terms is tolerated. An empty spec yields a Filter that
// matches nothing (Active() == false), so the scan output is unchanged.
package linefilter

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// lineRange is an inclusive [lo, hi] line-count range. An exact count N is
// stored as the range [N, N].
type lineRange struct {
	lo int
	hi int
}

// Filter decides whether a response body of a given line count should be
// filtered (suppressed) from output. The zero value matches nothing and is
// safe to use.
type Filter struct {
	ranges []lineRange
}

// Parse builds a Filter from a comma-separated line-count spec. An empty (or
// all-whitespace) spec returns an inactive Filter and no error. Malformed
// terms — non-numeric, negative, or reversed ranges — return an error so the
// operator learns immediately rather than silently filtering nothing.
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
				return nil, fmt.Errorf("linefilter: invalid range low bound in %q: %w", term, err)
			}
			hiN, err := parseNonNeg(strings.TrimSpace(hi))
			if err != nil {
				return nil, fmt.Errorf("linefilter: invalid range high bound in %q: %w", term, err)
			}
			if hiN < loN {
				return nil, fmt.Errorf("linefilter: reversed range %q: high (%d) < low (%d)", term, hiN, loN)
			}
			f.ranges = append(f.ranges, lineRange{lo: loN, hi: hiN})
			continue
		}

		n, err := parseNonNeg(term)
		if err != nil {
			return nil, fmt.Errorf("linefilter: invalid line count %q: %w", term, err)
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

// CountLines returns the number of newline-separated lines in a response body,
// matching ffuf's line-count semantics (the count of '\n' terminators). It is
// exported so callers can reuse the exact same definition the filter compares
// against.
func CountLines(body []byte) int {
	return bytes.Count(body, []byte{'\n'})
}

// Active reports whether the filter has any terms. When false, Match always
// returns false and callers can skip the check entirely.
func (f *Filter) Active() bool {
	return f != nil && len(f.ranges) > 0
}

// Match reports whether a response body with the given line count should be
// filtered (suppressed). It returns false for an inactive filter and for a
// negative count.
func (f *Filter) Match(lines int) bool {
	if !f.Active() || lines < 0 {
		return false
	}
	for _, r := range f.ranges {
		if lines >= r.lo && lines <= r.hi {
			return true
		}
	}
	return false
}

// MatchBody is a convenience wrapper that counts the lines in body and reports
// whether it should be filtered. Equivalent to f.Match(CountLines(body)).
func (f *Filter) MatchBody(body []byte) bool {
	if !f.Active() {
		return false
	}
	return f.Match(CountLines(body))
}
