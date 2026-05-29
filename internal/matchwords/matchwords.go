// Package matchwords parses a response word-count "require" spec and decides
// whether a given response body should be KEPT (reported) because its word
// count matches an allowlist.
//
// matchwords is the positive complement to wordfilter: where wordfilter's
// --filter-words SUPPRESSES unconfirmed "[responded]" responses whose body
// word count matches a known-noise count, matchwords' --match-words inverts the
// polarity — it KEEPS only the unconfirmed responses whose word count matches
// an interesting count and drops everything else. This is the classic ffuf
// "-mw" (match words) workflow, the positive twin of ffuf's "-fw", and the
// word-count sibling of matchsize's --match-size, matchcode's --match-code,
// matchtime's --match-time, and matchfilter's --match-regex. It completes the
// positive match family so every suppression filter has a mirror keep-gate.
//
// During LFI reconnaissance the traversal payloads against a single parameter
// overwhelmingly return one uniform soft-404 / WAF block page. Byte-size
// matching (--match-size) is the obvious tool, but it is brittle: many error
// templates embed a varying token — a request ID, a timestamp, a CSRF nonce, a
// cache buster — so the body length wobbles by a few bytes per request and a
// fixed --match-size cannot pin it. The *word count*, however, stays constant
// across those variants because only the content of one token changes, not the
// token count. --match-words lets the operator name the distinctive word
// count(s) where leaked file content lands and drop the dynamic-length noise
// that --match-size cannot, the inverse of naming the noise with --filter-words.
//
// The gates compose naturally with the rest of the family. During
// reconnaissance an operator first narrows the haystack with the positive match
// gates (--match-regex, --match-code, --match-size, --match-time, --match-words),
// then prunes residual noise from the kept set with the --filter-* suppressors.
// The gating order in the scan loop is: a confirmed hit is ALWAYS reported; an
// unconfirmed response is reported only if (every match gate is satisfied) AND
// none of the suppression filters fire.
//
// This NEVER touches confirmed hits. Confirmation in exhumed is content-based
// (see internal/detect): a body that satisfies an entry's confirm block is a
// hit regardless of how many words it contains. matchwords only governs the
// unconfirmed "[responded]" stream, turning it from "every body that responded"
// into "only the word counts worth a second look."
//
// Word count is defined exactly as ffuf defines it and as wordfilter.CountWords
// computes it (strings.Fields): the number of maximal runs of non-whitespace
// characters. The empty (or all-whitespace) body has a word count of zero.
//
// Spec grammar (the value of --match-words), comma-separated terms:
//
//	0            keep bodies with zero words
//	42           keep bodies with exactly 42 words
//	10-20        keep the inclusive range [10, 20] words
//	0,42,10-20   any combination
//
// Whitespace around terms is tolerated. An empty spec yields a Filter that
// keeps everything (Active() == false), so the scan output is unchanged.
//
// Word counts are non-negative. Negative terms, non-numeric terms, and reversed
// ranges are rejected at parse time so the operator learns immediately rather
// than silently keeping nothing.
package matchwords

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bugsyhewitt/exhumed/internal/wordfilter"
)

// wordRange is an inclusive [lo, hi] word-count range. An exact count N is
// stored as the range [N, N].
type wordRange struct {
	lo int
	hi int
}

// Filter decides whether a response body of a given word count should be kept
// (reported) because it matches a require-words allowlist. The zero value is
// inactive (keeps everything) and is safe to use.
type Filter struct {
	ranges []wordRange
}

// Parse builds a Filter from a comma-separated word-count allowlist spec. An
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
				return nil, fmt.Errorf("matchwords: invalid range low bound in %q: %w", term, err)
			}
			hiN, err := parseNonNeg(strings.TrimSpace(hi))
			if err != nil {
				return nil, fmt.Errorf("matchwords: invalid range high bound in %q: %w", term, err)
			}
			if hiN < loN {
				return nil, fmt.Errorf("matchwords: reversed range %q: high (%d) < low (%d)", term, hiN, loN)
			}
			f.ranges = append(f.ranges, wordRange{lo: loN, hi: hiN})
			continue
		}

		n, err := parseNonNeg(term)
		if err != nil {
			return nil, fmt.Errorf("matchwords: invalid word count %q: %w", term, err)
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

// Active reports whether the filter has any terms. When false, Keep always
// returns true (keep everything) and callers can skip the check entirely.
func (f *Filter) Active() bool {
	return f != nil && len(f.ranges) > 0
}

// Keep reports whether a response body of the given word count should be kept
// (reported) because it matches the allowlist. An inactive filter keeps
// everything, returning true. A negative count is never kept by an active
// filter.
func (f *Filter) Keep(words int) bool {
	if !f.Active() {
		return true
	}
	if words < 0 {
		return false
	}
	for _, r := range f.ranges {
		if words >= r.lo && words <= r.hi {
			return true
		}
	}
	return false
}

// KeepBody is a convenience wrapper that counts the words in body using the
// exact same definition the filter compares against (wordfilter.CountWords) and
// reports whether the body should be kept. Equivalent to
// f.Keep(wordfilter.CountWords(body)).
func (f *Filter) KeepBody(body []byte) bool {
	if !f.Active() {
		return true
	}
	return f.Keep(wordfilter.CountWords(body))
}
