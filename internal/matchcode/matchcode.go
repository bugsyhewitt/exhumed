// Package matchcode parses an HTTP status-code "require" spec and decides
// whether a given response status code should be KEPT (reported) because it
// matches the allowlist.
//
// matchcode is the positive complement to codefilter: where codefilter's
// --filter-code SUPPRESSES unconfirmed "[responded]" responses whose status
// matches a known-noise code, matchcode's --match-code inverts the polarity —
// it KEEPS only the unconfirmed responses whose status matches an interesting
// code and drops everything else. This is the classic ffuf "-mc" (match code)
// workflow, the positive twin of ffuf's "-fc", and the status-code sibling of
// matchfilter's --match-regex.
//
// During LFI reconnaissance the traversal payloads against a single parameter
// overwhelmingly return one uniform status (a 200 default page, a 404, a 403
// from a WAF). The signal is the minority status: a 500 from a crashing
// include() sink, a 200 that differs from the uniform 404, a 302 that only
// fires when the path resolves. --match-code lets the operator name the
// status(es) worth a second look and drop the rest of the unconfirmed stream,
// the inverse of naming the noise with --filter-code.
//
// The two compose naturally with the other gates. During reconnaissance an
// operator first narrows the haystack with --match-code (e.g. only show 500s),
// then prunes residual noise from the kept set with the --filter-* suppressors.
// The gating order in the scan loop is: a confirmed hit is ALWAYS reported; an
// unconfirmed response is reported only if (every match gate is satisfied) AND
// none of the suppression filters fire.
//
// This NEVER touches confirmed hits. Confirmation in exhumed is content-based
// (see internal/detect): a body that satisfies an entry's confirm block is a
// hit regardless of its status code. matchcode only governs the unconfirmed
// "[responded]" stream, turning it from "every status that responded" into
// "only the statuses worth a second look."
//
// Spec grammar (the value of --match-code), comma-separated terms:
//
//	500          keep exactly status 500
//	200,500      keep multiple exact codes
//	500-599      keep the inclusive range [500, 599] (all 5xx)
//	200,500-599  any combination
//
// Whitespace around terms is tolerated. An empty spec yields a Filter that
// keeps everything (Active() == false), so the scan output is unchanged.
//
// Valid HTTP status codes are 100–599. Codes outside that range, non-numeric
// terms, and reversed ranges are rejected at parse time so the operator learns
// immediately rather than silently keeping nothing.
package matchcode

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

// Filter decides whether a response status code should be kept (reported)
// because it matches a require-code allowlist. The zero value is inactive
// (keeps everything) and is safe to use.
type Filter struct {
	ranges []codeRange
}

// Parse builds a Filter from a comma-separated status-code allowlist spec. An
// empty (or all-whitespace) spec returns an inactive Filter and no error —
// callers treat an inactive filter as "keep everything." Malformed terms —
// non-numeric, out-of-range (not in 100–599), or reversed ranges — return an
// error so the operator learns immediately rather than silently keeping
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
				return nil, fmt.Errorf("matchcode: invalid range low bound in %q: %w", term, err)
			}
			hiN, err := parseCode(strings.TrimSpace(hi))
			if err != nil {
				return nil, fmt.Errorf("matchcode: invalid range high bound in %q: %w", term, err)
			}
			if hiN < loN {
				return nil, fmt.Errorf("matchcode: reversed range %q: high (%d) < low (%d)", term, hiN, loN)
			}
			f.ranges = append(f.ranges, codeRange{lo: loN, hi: hiN})
			continue
		}

		n, err := parseCode(term)
		if err != nil {
			return nil, fmt.Errorf("matchcode: invalid status code %q: %w", term, err)
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

// Active reports whether the filter has any terms. When false, Keep always
// returns true (keep everything) and callers can skip the check entirely.
func (f *Filter) Active() bool {
	return f != nil && len(f.ranges) > 0
}

// Keep reports whether a response with the given status code should be kept
// (reported) because it matches the allowlist. An inactive filter keeps
// everything, returning true.
func (f *Filter) Keep(code int) bool {
	if !f.Active() {
		return true
	}
	for _, r := range f.ranges {
		if code >= r.lo && code <= r.hi {
			return true
		}
	}
	return false
}
