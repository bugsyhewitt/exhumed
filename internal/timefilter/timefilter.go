// Package timefilter parses response-time filter specs and decides whether a
// given response round-trip time should be suppressed from output.
//
// During a scan, the signal for a real LFI hit is content-based (see
// internal/detect), but timing is a cheap, orthogonal noise discriminator that
// the size/code/regex filters cannot capture. Two common cases:
//
//   - A backend reverse-proxy or WAF returns its uniform block/soft-404 page
//     almost instantly (sub-millisecond cache hit), while a genuine file read
//     touches disk and takes longer — filter out the fast noise with ">5ms".
//   - A slow upstream timing out near the deadline floods output with
//     uniformly slow non-hits — filter the slow noise with "<2s".
//
// timefilter implements the classic ffuf "-ft" workflow over response time,
// completing the noise-suppression set alongside --filter-size (respfilter),
// --filter-code (codefilter), and --filter-regex (bodyfilter).
//
// This NEVER touches confirmed hits. A body that satisfies an entry's confirm
// block is a hit regardless of how fast or slow it responded. timefilter only
// quiets the unconfirmed "[responded]" stream — a finer-grained scalpel than
// --only-hits.
//
// Spec grammar (the value of --filter-time), comma-separated terms. Each term
// is a comparator (> >= < <=) followed by a Go duration literal:
//
//	>500ms        suppress responses slower than 500ms
//	<100ms        suppress responses faster than 100ms
//	>=1s          suppress responses at or above 1 second
//	<=50ms        suppress responses at or below 50ms
//	>5ms,<2s      suppress the very fast AND the very slow (any term matches)
//
// A bare number with no comparator is rejected — timing filters are inherently
// directional, so the operator must say which side is noise. Durations use Go
// syntax (ns, us/µs, ms, s, m, h). Whitespace around terms is tolerated. An
// empty spec yields a Filter that matches nothing (Active() == false), so the
// scan output is unchanged.
package timefilter

import (
	"fmt"
	"strings"
	"time"
)

// op is a duration comparator.
type op int

const (
	opGT  op = iota // >
	opGTE           // >=
	opLT            // <
	opLTE           // <=
)

// bound is one comparator/threshold pair, e.g. ">= 1s".
type bound struct {
	cmp op
	dur time.Duration
}

// Filter decides whether a response of a given round-trip duration should be
// filtered (suppressed) from output. The zero value matches nothing and is
// safe to use.
type Filter struct {
	bounds []bound
}

// Parse builds a Filter from a comma-separated time spec. An empty (or
// all-whitespace) spec returns an inactive Filter and no error. Malformed
// terms — a missing comparator, a bad duration literal, or a negative
// threshold — return an error so the operator learns immediately rather than
// silently filtering nothing.
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

		cmp, rest, err := splitComparator(term)
		if err != nil {
			return nil, fmt.Errorf("timefilter: %w", err)
		}

		dur, err := time.ParseDuration(strings.TrimSpace(rest))
		if err != nil {
			return nil, fmt.Errorf("timefilter: invalid duration in %q: %w", term, err)
		}
		if dur < 0 {
			return nil, fmt.Errorf("timefilter: negative duration in %q", term)
		}

		f.bounds = append(f.bounds, bound{cmp: cmp, dur: dur})
	}

	return f, nil
}

// splitComparator peels a leading comparator (>= <= > <) off a term and returns
// it along with the remaining duration text. The two-character operators are
// checked first so ">=" is not misread as ">".
func splitComparator(term string) (op, string, error) {
	switch {
	case strings.HasPrefix(term, ">="):
		return opGTE, term[2:], nil
	case strings.HasPrefix(term, "<="):
		return opLTE, term[2:], nil
	case strings.HasPrefix(term, ">"):
		return opGT, term[1:], nil
	case strings.HasPrefix(term, "<"):
		return opLT, term[1:], nil
	default:
		return 0, "", fmt.Errorf("term %q must start with a comparator (> >= < <=), e.g. \">500ms\"", term)
	}
}

// Active reports whether the filter has any terms. When false, Match always
// returns false and callers can skip the check entirely.
func (f *Filter) Active() bool {
	return f != nil && len(f.bounds) > 0
}

// Match reports whether a response with the given round-trip duration should be
// filtered (suppressed). It returns false for an inactive filter and for a
// negative duration. A response is suppressed if it satisfies ANY bound.
func (f *Filter) Match(d time.Duration) bool {
	if !f.Active() || d < 0 {
		return false
	}
	for _, b := range f.bounds {
		switch b.cmp {
		case opGT:
			if d > b.dur {
				return true
			}
		case opGTE:
			if d >= b.dur {
				return true
			}
		case opLT:
			if d < b.dur {
				return true
			}
		case opLTE:
			if d <= b.dur {
				return true
			}
		}
	}
	return false
}
