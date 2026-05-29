// Package matchsize parses a response-size "require" spec and decides whether a
// given response body length should be KEPT (reported) because it matches an
// allowlist of byte lengths.
//
// matchsize is the positive complement to respfilter: where respfilter's
// --filter-size SUPPRESSES unconfirmed "[responded]" responses whose body
// length matches a known-noise size, matchsize's --match-size inverts the
// polarity — it KEEPS only the unconfirmed responses whose body length matches
// an interesting size and drops everything else. This is the classic ffuf
// "-ms" (match size) workflow, the positive twin of ffuf's "-fs", and the
// response-size sibling of matchcode's --match-code and matchfilter's
// --match-regex.
//
// During LFI reconnaissance the traversal payloads against a single parameter
// overwhelmingly return one uniform body size (a fixed soft-404 template, a WAF
// block page, an empty body). The signal is the minority size: a longer body
// where an include() actually leaked file content, a distinctively-sized error
// that only a real read produces. --match-size lets the operator name the body
// length(s) worth a second look and drop the rest of the unconfirmed stream,
// the inverse of naming the noise with --filter-size.
//
// The gates compose naturally with the rest of the family. During
// reconnaissance an operator first narrows the haystack with the positive
// match gates (--match-regex, --match-code, --match-size), then prunes residual
// noise from the kept set with the --filter-* suppressors. The gating order in
// the scan loop is: a confirmed hit is ALWAYS reported; an unconfirmed response
// is reported only if (every match gate is satisfied) AND none of the
// suppression filters fire.
//
// This NEVER touches confirmed hits. Confirmation in exhumed is content-based
// (see internal/detect): a body that satisfies an entry's confirm block is a
// hit regardless of its size. matchsize only governs the unconfirmed
// "[responded]" stream, turning it from "every body that responded" into "only
// the body sizes worth a second look."
//
// Spec grammar (the value of --match-size), comma-separated terms:
//
//	413          keep exactly a 413-byte body
//	0            keep zero-length bodies
//	100-200      keep the inclusive range [100, 200]
//	413,0,100-200 any combination
//
// Whitespace around terms is tolerated. An empty spec yields a Filter that
// keeps everything (Active() == false), so the scan output is unchanged.
//
// Sizes are non-negative byte lengths. Negative terms, non-numeric terms, and
// reversed ranges are rejected at parse time so the operator learns immediately
// rather than silently keeping nothing.
package matchsize

import (
	"fmt"
	"strconv"
	"strings"
)

// sizeRange is an inclusive [lo, hi] byte-length range. An exact size N is
// stored as the range [N, N].
type sizeRange struct {
	lo int
	hi int
}

// Filter decides whether a response body of a given length should be kept
// (reported) because it matches a require-size allowlist. The zero value is
// inactive (keeps everything) and is safe to use.
type Filter struct {
	ranges []sizeRange
}

// Parse builds a Filter from a comma-separated size allowlist spec. An empty
// (or all-whitespace) spec returns an inactive Filter and no error — callers
// treat an inactive filter as "keep everything." Malformed terms — non-numeric,
// negative, or reversed ranges — return an error so the operator learns
// immediately rather than silently keeping nothing.
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
				return nil, fmt.Errorf("matchsize: invalid range low bound in %q: %w", term, err)
			}
			hiN, err := parseNonNeg(strings.TrimSpace(hi))
			if err != nil {
				return nil, fmt.Errorf("matchsize: invalid range high bound in %q: %w", term, err)
			}
			if hiN < loN {
				return nil, fmt.Errorf("matchsize: reversed range %q: high (%d) < low (%d)", term, hiN, loN)
			}
			f.ranges = append(f.ranges, sizeRange{lo: loN, hi: hiN})
			continue
		}

		n, err := parseNonNeg(term)
		if err != nil {
			return nil, fmt.Errorf("matchsize: invalid size %q: %w", term, err)
		}
		f.ranges = append(f.ranges, sizeRange{lo: n, hi: n})
	}

	return f, nil
}

// parseNonNeg parses a non-negative decimal integer byte length.
func parseNonNeg(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("not an integer")
	}
	if n < 0 {
		return 0, fmt.Errorf("negative size %d", n)
	}
	return n, nil
}

// Active reports whether the filter has any terms. When false, Keep always
// returns true (keep everything) and callers can skip the check entirely.
func (f *Filter) Active() bool {
	return f != nil && len(f.ranges) > 0
}

// Keep reports whether a response body of n bytes should be kept (reported)
// because it matches the allowlist. An inactive filter keeps everything,
// returning true. A negative n is never kept by an active filter.
func (f *Filter) Keep(n int) bool {
	if !f.Active() {
		return true
	}
	if n < 0 {
		return false
	}
	for _, r := range f.ranges {
		if n >= r.lo && n <= r.hi {
			return true
		}
	}
	return false
}
