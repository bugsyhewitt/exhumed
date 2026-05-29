// Package respfilter parses response-size filter specs and decides whether a
// given response body length should be suppressed from output.
//
// During a scan, generic web apps return a fixed-size error page for every
// path that does not exist (a 200 "file not found" template, a soft-404, a WAF
// block page, etc.). Those uniform-size responses flood the non-hit output and
// bury the signal. respfilter implements the classic ffuf/gobuster "-fs"
// workflow: the operator names the byte length(s) of the known noise and
// exhumed drops responses of exactly those sizes from the "[responded]" stream.
//
// This NEVER touches confirmed hits. Confirmation in exhumed is content-based
// (see internal/detect): a body that satisfies an entry's confirm block is a
// hit regardless of its size. respfilter only quiets the unconfirmed
// "[responded]" noise that --only-hits would otherwise have to suppress
// wholesale. It is a finer-grained scalpel than --only-hits.
//
// Spec grammar (the value of --filter-size), comma-separated terms:
//
//	413          exact body length of 413 bytes
//	0            zero-length bodies
//	100-200      inclusive range [100, 200]
//	413,0,100-200 any combination
//
// Whitespace around terms is tolerated. An empty spec yields a Filter that
// matches nothing (Active() == false), so the scan output is unchanged.
package respfilter

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

// Filter decides whether a response body of a given length should be filtered
// (suppressed) from output. The zero value matches nothing and is safe to use.
type Filter struct {
	ranges []sizeRange
}

// Parse builds a Filter from a comma-separated size spec. An empty (or
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
				return nil, fmt.Errorf("respfilter: invalid range low bound in %q: %w", term, err)
			}
			hiN, err := parseNonNeg(strings.TrimSpace(hi))
			if err != nil {
				return nil, fmt.Errorf("respfilter: invalid range high bound in %q: %w", term, err)
			}
			if hiN < loN {
				return nil, fmt.Errorf("respfilter: reversed range %q: high (%d) < low (%d)", term, hiN, loN)
			}
			f.ranges = append(f.ranges, sizeRange{lo: loN, hi: hiN})
			continue
		}

		n, err := parseNonNeg(term)
		if err != nil {
			return nil, fmt.Errorf("respfilter: invalid size %q: %w", term, err)
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

// Active reports whether the filter has any terms. When false, Match always
// returns false and callers can skip the check entirely.
func (f *Filter) Active() bool {
	return f != nil && len(f.ranges) > 0
}

// Match reports whether a response body of n bytes should be filtered
// (suppressed). It returns false for an inactive filter and for negative n.
func (f *Filter) Match(n int) bool {
	if !f.Active() || n < 0 {
		return false
	}
	for _, r := range f.ranges {
		if n >= r.lo && n <= r.hi {
			return true
		}
	}
	return false
}
