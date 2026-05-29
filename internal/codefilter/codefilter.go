// Package codefilter parses HTTP status-code filter specs and decides whether a
// given response status code should be suppressed from output.
//
// During a scan, generic web apps return a uniform status code for every path
// that does not exist: a hard 404, a 403 from a WAF, a 500 from a crashing
// include sink, or a 302 redirect to a login page. Those uniform statuses flood
// the non-hit output and bury the signal. codefilter is the status-code
// companion to respfilter's size-based --filter-size: it implements the classic
// ffuf "-fc" / feroxbuster "--filter-status" workflow. The operator names the
// status code(s) of the known noise and exhumed drops responses with exactly
// those codes from the "[responded]" stream.
//
// This NEVER touches confirmed hits. Confirmation in exhumed is content-based
// (see internal/detect): a body that satisfies an entry's confirm block is a
// hit regardless of its status code. codefilter only quiets the unconfirmed
// "[responded]" noise that --only-hits would otherwise suppress wholesale. It
// is a finer-grained scalpel than --only-hits, and composes with --filter-size:
// a response is suppressed if EITHER filter matches it.
//
// Spec grammar (the value of --filter-code), comma-separated terms:
//
//	404          exact status code 404
//	403,500      multiple exact codes
//	400-499      inclusive range [400, 499] (all 4xx)
//	302,400-499  any combination
//
// Whitespace around terms is tolerated. An empty spec yields a Filter that
// matches nothing (Active() == false), so the scan output is unchanged.
//
// Valid HTTP status codes are 100–599. Codes outside that range, non-numeric
// terms, and reversed ranges are rejected at parse time so the operator learns
// immediately rather than silently filtering nothing.
package codefilter

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	minCode = 100
	maxCode = 599
)

// codeRange is an inclusive [lo, hi] status-code range. An exact code N is
// stored as the range [N, N].
type codeRange struct {
	lo int
	hi int
}

// Filter decides whether a response status code should be filtered
// (suppressed) from output. The zero value matches nothing and is safe to use.
type Filter struct {
	ranges []codeRange
}

// Parse builds a Filter from a comma-separated status-code spec. An empty (or
// all-whitespace) spec returns an inactive Filter and no error. Malformed terms
// — non-numeric, out-of-range (not in 100–599), or reversed ranges — return an
// error so the operator learns immediately rather than silently filtering
// nothing.
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
			loN, err := parseCode(strings.TrimSpace(lo))
			if err != nil {
				return nil, fmt.Errorf("codefilter: invalid range low bound in %q: %w", term, err)
			}
			hiN, err := parseCode(strings.TrimSpace(hi))
			if err != nil {
				return nil, fmt.Errorf("codefilter: invalid range high bound in %q: %w", term, err)
			}
			if hiN < loN {
				return nil, fmt.Errorf("codefilter: reversed range %q: high (%d) < low (%d)", term, hiN, loN)
			}
			f.ranges = append(f.ranges, codeRange{lo: loN, hi: hiN})
			continue
		}

		n, err := parseCode(term)
		if err != nil {
			return nil, fmt.Errorf("codefilter: invalid status code %q: %w", term, err)
		}
		f.ranges = append(f.ranges, codeRange{lo: n, hi: n})
	}

	return f, nil
}

// parseCode parses a decimal HTTP status code and bounds-checks it to the
// valid 100–599 range.
func parseCode(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("not an integer")
	}
	if n < minCode || n > maxCode {
		return 0, fmt.Errorf("status code %d out of range (must be %d-%d)", n, minCode, maxCode)
	}
	return n, nil
}

// Active reports whether the filter has any terms. When false, Match always
// returns false and callers can skip the check entirely.
func (f *Filter) Active() bool {
	return f != nil && len(f.ranges) > 0
}

// Match reports whether a response with the given status code should be
// filtered (suppressed). It returns false for an inactive filter.
func (f *Filter) Match(code int) bool {
	if !f.Active() {
		return false
	}
	for _, r := range f.ranges {
		if code >= r.lo && code <= r.hi {
			return true
		}
	}
	return false
}
