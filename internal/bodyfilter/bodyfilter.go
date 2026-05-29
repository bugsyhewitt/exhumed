// Package bodyfilter parses response-body regex filter specs and decides whether
// a given response body should be suppressed from output.
//
// During a scan, generic web apps return a uniform "page" for every path that
// does not exist: a soft-404 HTML template, a framework error page, a "file not
// found" banner, or a WAF challenge — all served with a 200 and a body whose
// length varies enough that --filter-size can't catch them, yet they share a
// recognisable phrase ("Not Found", "Access Denied", a CSRF token wrapper). Those
// uniform bodies flood the non-hit output and bury the signal. bodyfilter is the
// body-content companion to respfilter's size-based --filter-size and
// codefilter's status-based --filter-code: it implements the classic ffuf "-fr"
// (filter regex) workflow. The operator names a regex that matches the known
// noise body and exhumed drops responses whose body matches from the
// "[responded]" stream.
//
// This NEVER touches confirmed hits. Confirmation in exhumed is content-based
// (see internal/detect): a body that satisfies an entry's confirm block is a hit
// regardless of what it otherwise contains. bodyfilter only quiets the
// unconfirmed "[responded]" noise that --only-hits would otherwise suppress
// wholesale. It is a finer-grained scalpel than --only-hits, and composes with
// --filter-size and --filter-code: a response is suppressed if ANY of the three
// filters matches it.
//
// Spec grammar (the value of --filter-regex): a single Go (RE2) regular
// expression, matched against the response body interpreted as a UTF-8 string.
// The match is a "contains" match (the pattern need not anchor to the whole
// body); use ^ and $ explicitly if whole-body anchoring is wanted. Examples:
//
//	Not Found             bodies containing the literal phrase "Not Found"
//	(?i)access denied     case-insensitive "access denied"
//	<title>404</title>    a specific error-page title
//
// An empty spec yields a Filter that matches nothing (Active() == false), so the
// scan output is unchanged. A malformed regex is rejected at parse time so the
// operator learns immediately rather than silently filtering nothing.
package bodyfilter

import (
	"fmt"
	"regexp"
	"strings"
)

// Filter decides whether a response body should be filtered (suppressed) from
// output. The zero value matches nothing and is safe to use.
type Filter struct {
	re *regexp.Regexp
}

// Parse builds a Filter from a single response-body regex spec. An empty (or
// all-whitespace) spec returns an inactive Filter and no error. A regex that
// fails to compile returns an error so the operator learns immediately rather
// than silently filtering nothing.
//
// Leading and trailing whitespace around the spec is trimmed, since a regex
// rarely intends to depend on it and a stray shell-quoting space is a common
// mistake. Whitespace inside the pattern is preserved.
func Parse(spec string) (*Filter, error) {
	f := &Filter{}
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return f, nil
	}

	re, err := regexp.Compile(spec)
	if err != nil {
		return nil, fmt.Errorf("bodyfilter: invalid regex %q: %w", spec, err)
	}
	f.re = re
	return f, nil
}

// Active reports whether the filter has a compiled pattern. When false, Match
// always returns false and callers can skip the check entirely.
func (f *Filter) Active() bool {
	return f != nil && f.re != nil
}

// Match reports whether a response with the given body should be filtered
// (suppressed). The body is matched as a UTF-8 string with a "contains"
// (unanchored) match. It returns false for an inactive filter.
func (f *Filter) Match(body []byte) bool {
	if !f.Active() {
		return false
	}
	return f.re.Match(body)
}
