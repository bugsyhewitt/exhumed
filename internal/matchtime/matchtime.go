// Package matchtime parses a response-time "require" spec and decides whether a
// given response round-trip time should be KEPT (reported) because it satisfies
// a comparator bound.
//
// matchtime is the positive complement to timefilter: where timefilter's
// --filter-time SUPPRESSES unconfirmed "[responded]" responses whose round-trip
// duration satisfies a comparator bound, matchtime's --match-time inverts the
// polarity — it KEEPS only the unconfirmed responses whose duration satisfies a
// bound and drops everything else. This is the classic ffuf "-mt" (match time)
// workflow, the positive twin of ffuf's "-ft", and the response-time sibling of
// matchcode's --match-code, matchsize's --match-size, and matchfilter's
// --match-regex.
//
// During LFI reconnaissance timing is a cheap, orthogonal signal the
// size/code/regex matchers cannot capture. Two common cases:
//
//   - A genuine include() touches disk and is measurably slower than the uniform
//     sub-millisecond cache/WAF soft-404 that dominates the stream — keep only
//     the slow minority with ">50ms".
//   - A specific backend path is known to respond in a narrow latency band —
//     keep only that band with ">100ms,<400ms" (any bound satisfied keeps the
//     response, so a band is expressed as the union of its edges; see Match).
//
// The gates compose naturally with the rest of the family. During reconnaissance
// an operator first narrows the haystack with the positive match gates
// (--match-regex, --match-code, --match-size, --match-time), then prunes residual
// noise from the kept set with the --filter-* suppressors. The gating order in
// the scan loop is: a confirmed hit is ALWAYS reported; an unconfirmed response
// is reported only if (every match gate is satisfied) AND none of the
// suppression filters fire.
//
// This NEVER touches confirmed hits. Confirmation in exhumed is content-based
// (see internal/detect): a body that satisfies an entry's confirm block is a hit
// regardless of how fast or slow it responded. matchtime only governs the
// unconfirmed "[responded]" stream, turning it from "every body that responded"
// into "only the round-trip times worth a second look."
//
// Spec grammar (the value of --match-time), comma-separated terms. Each term is
// a comparator (> >= < <=) followed by a Go duration literal:
//
//	>50ms         keep responses slower than 50ms
//	>=1s          keep responses at or above 1 second
//	<5ms          keep responses faster than 5ms
//	<=200ms       keep responses at or below 200ms
//	>1s,<5ms      keep the very slow OR the very fast (any term keeps)
//
// A bare number with no comparator is rejected — timing gates are inherently
// directional, so the operator must say which side is interesting. Durations use
// Go syntax (ns, us/µs, ms, s, m, h). Whitespace around terms is tolerated. An
// empty spec yields a Filter that keeps everything (Active() == false), so the
// scan output is unchanged.
package matchtime

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
// kept (reported) because it satisfies a require-time allowlist. The zero value
// is inactive (keeps everything) and is safe to use.
type Filter struct {
	bounds []bound
}

// Parse builds a Filter from a comma-separated time spec. An empty (or
// all-whitespace) spec returns an inactive Filter and no error — callers treat
// an inactive filter as "keep everything." Malformed terms — a missing
// comparator, a bad duration literal, or a negative threshold — return an error
// so the operator learns immediately rather than silently keeping nothing.
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
			return nil, fmt.Errorf("matchtime: %w", err)
		}

		dur, err := time.ParseDuration(strings.TrimSpace(rest))
		if err != nil {
			return nil, fmt.Errorf("matchtime: invalid duration in %q: %w", term, err)
		}
		if dur < 0 {
			return nil, fmt.Errorf("matchtime: negative duration in %q", term)
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
		return 0, "", fmt.Errorf("term %q must start with a comparator (> >= < <=), e.g. \">50ms\"", term)
	}
}

// Active reports whether the filter has any terms. When false, Keep always
// returns true (keep everything) and callers can skip the check entirely.
func (f *Filter) Active() bool {
	return f != nil && len(f.bounds) > 0
}

// Keep reports whether a response with the given round-trip duration should be
// kept (reported) because it satisfies the allowlist. An inactive filter keeps
// everything, returning true. A negative duration is never kept by an active
// filter. A response is kept if it satisfies ANY bound.
func (f *Filter) Keep(d time.Duration) bool {
	if !f.Active() {
		return true
	}
	if d < 0 {
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
