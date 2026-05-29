// Package wordfilter parses response word-count filter specs and decides
// whether a given response body should be suppressed from output based on the
// number of whitespace-separated words it contains.
//
// During a scan, generic web apps return a soft-404 / WAF block page for every
// path that does not exist. Byte-size filtering (--filter-size) is the obvious
// tool for that noise, but it is brittle: many error templates embed a varying
// token — a request ID, a timestamp, a CSRF nonce, a cache buster — so the body
// length wobbles by a few bytes per request and a fixed --filter-size misses
// most of them. The *word count*, however, stays constant across those
// variants because only the content of one token changes, not the token count.
// Word-count filtering catches the dynamic-length noise that size filtering
// cannot, which is exactly why ffuf exposes "-fw" alongside "-fs".
//
// wordfilter implements that classic ffuf "-fw" workflow, completing the
// noise-suppression set alongside --filter-size (respfilter), --filter-code
// (codefilter), --filter-regex (bodyfilter), and --filter-time (timefilter).
//
// This NEVER touches confirmed hits. Confirmation in exhumed is content-based
// (see internal/detect): a body that satisfies an entry's confirm block is a
// hit regardless of how many words it contains. wordfilter only quiets the
// unconfirmed "[responded]" stream — a finer-grained scalpel than --only-hits.
//
// Word count is defined exactly as ffuf defines it and as strings.Fields
// computes it: the number of maximal runs of non-whitespace characters. The
// empty (or all-whitespace) body has a word count of zero.
//
// Spec grammar (the value of --filter-words), comma-separated terms:
//
//	0            bodies with zero words
//	42           bodies with exactly 42 words
//	10-20        inclusive range [10, 20] words
//	0,42,10-20   any combination
//
// Whitespace around terms is tolerated. An empty spec yields a Filter that
// matches nothing (Active() == false), so the scan output is unchanged.
package wordfilter

import (
	"fmt"
	"strconv"
	"strings"
)

// wordRange is an inclusive [lo, hi] word-count range. An exact count N is
// stored as the range [N, N].
type wordRange struct {
	lo int
	hi int
}

// Filter decides whether a response body of a given word count should be
// filtered (suppressed) from output. The zero value matches nothing and is
// safe to use.
type Filter struct {
	ranges []wordRange
}

// Parse builds a Filter from a comma-separated word-count spec. An empty (or
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
				return nil, fmt.Errorf("wordfilter: invalid range low bound in %q: %w", term, err)
			}
			hiN, err := parseNonNeg(strings.TrimSpace(hi))
			if err != nil {
				return nil, fmt.Errorf("wordfilter: invalid range high bound in %q: %w", term, err)
			}
			if hiN < loN {
				return nil, fmt.Errorf("wordfilter: reversed range %q: high (%d) < low (%d)", term, hiN, loN)
			}
			f.ranges = append(f.ranges, wordRange{lo: loN, hi: hiN})
			continue
		}

		n, err := parseNonNeg(term)
		if err != nil {
			return nil, fmt.Errorf("wordfilter: invalid word count %q: %w", term, err)
		}
		f.ranges = append(f.ranges, wordRange{lo: n, hi: n})
	}

	return f, nil
}

// parseNonNeg parses a non-negative decimal integer word count.
func parseNonNeg(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("not an integer")
	}
	if n < 0 {
		return 0, fmt.Errorf("negative word count %d", n)
	}
	return n, nil
}

// CountWords returns the number of whitespace-separated words in a response
// body, matching ffuf's word-count semantics (strings.Fields). It is exported
// so callers can reuse the exact same definition the filter compares against.
func CountWords(body []byte) int {
	return len(strings.Fields(string(body)))
}

// Active reports whether the filter has any terms. When false, Match always
// returns false and callers can skip the check entirely.
func (f *Filter) Active() bool {
	return f != nil && len(f.ranges) > 0
}

// Match reports whether a response body with the given word count should be
// filtered (suppressed). It returns false for an inactive filter and for a
// negative count.
func (f *Filter) Match(words int) bool {
	if !f.Active() || words < 0 {
		return false
	}
	for _, r := range f.ranges {
		if words >= r.lo && words <= r.hi {
			return true
		}
	}
	return false
}

// MatchBody is a convenience wrapper that counts the words in body and reports
// whether it should be filtered. Equivalent to f.Match(CountWords(body)).
func (f *Filter) MatchBody(body []byte) bool {
	if !f.Active() {
		return false
	}
	return f.Match(CountWords(body))
}
