// Package headerfilter parses one or more response-header "noise" specs and
// decides whether a given response should be SUPPRESSED (filtered) from output
// because its headers match a known-noise signature.
//
// headerfilter is the negative twin of matchheaders: where matchheaders's
// --match-headers KEEPS only the unconfirmed "[responded]" responses whose
// headers satisfy every require rule, headerfilter's --filter-headers inverts
// the polarity — it SUPPRESSES the unconfirmed responses whose headers match a
// known-noise rule and keeps everything else. It is the header-surface companion
// to bodyfilter's --filter-regex (body), respfilter's --filter-size (length),
// codefilter's --filter-code (status), timefilter's --filter-time (latency),
// wordfilter's --filter-words (word count), and linefilter's --filter-lines
// (line count). Together they let an operator quiet the uniform soft-404/WAF
// noise from whichever surface distinguishes it.
//
// The header surface matters because a generic web app frequently stamps its
// "file not found" page with a tell-tale header block: a fixed Server banner, an
// X-Cache: HIT from a CDN that short-circuits every miss, an X-Powered-By the
// real file reads do not carry, a Content-Type: text/html on the soft-404
// template where a leaked file would sniff to text/plain. When the noise body's
// length, word count, and status are too variable to pin with --filter-size /
// --filter-words / --filter-code, its header block is often constant.
// --filter-headers names that constant signature and drops it.
//
// Spec model: the flag is repeatable. Each occurrence is one
// "Header-Name: regex" pair:
//
//	--filter-headers 'Server: cloudflare'
//	--filter-headers 'X-Cache: HIT'
//	--filter-headers 'Content-Type: text/html'
//
// Header-Name matching is case-insensitive (HTTP header names are
// case-insensitive and Go canonicalises them). The regex is a Go (RE2)
// "contains" match against each value of that header; a rule is satisfied if the
// named header is present AND at least one of its values matches. A header that
// is absent never satisfies its rule.
//
// When more than one pair is supplied they compose as a DISJUNCTION: a response
// is suppressed if ANY rule matches. This mirrors the suppression semantics of
// the rest of the filter family (a response is dropped if any --filter-* gate
// fires) and is the deliberate opposite of matchheaders's conjunction — there,
// every keep-rule must pass; here, any drop-rule is enough.
//
// An empty spec set yields a Filter that matches nothing (Active() == false), so
// the scan output is unchanged. A malformed pair — missing colon, empty header
// name, or a regex that fails to compile — is rejected at parse time so the
// operator learns immediately rather than silently filtering nothing.
//
// This NEVER touches confirmed hits. Confirmation in exhumed is content-based
// (see internal/detect): a body that satisfies an entry's confirm block is a hit
// regardless of its headers. headerfilter only quiets the unconfirmed
// "[responded]" noise that --only-hits would otherwise suppress wholesale. It is
// a finer-grained scalpel than --only-hits.
package headerfilter

import (
	"fmt"
	"net/http"
	"net/textproto"
	"regexp"
	"strings"
)

// headerRule is one "Header-Name: regex" noise signature. name is stored in the
// canonical MIME header form so lookups against an http.Header are
// case-insensitive.
type headerRule struct {
	name string
	re   *regexp.Regexp
}

// Filter decides whether a response should be suppressed (filtered) because its
// headers match a known-noise rule. The zero value matches nothing (keeps
// everything) and is safe to use.
type Filter struct {
	rules []headerRule
}

// Parse builds a Filter from a slice of "Header-Name: regex" specs (typically
// one per repeated --filter-headers flag). An empty slice — or a slice whose
// entries are all blank — returns an inactive Filter and no error; callers treat
// an inactive filter as "suppress nothing." A malformed pair returns an error so
// the operator learns immediately rather than silently filtering nothing.
func Parse(specs []string) (*Filter, error) {
	f := &Filter{}
	for _, raw := range specs {
		spec := strings.TrimSpace(raw)
		if spec == "" {
			// A blank repeat is tolerated rather than fatal.
			continue
		}

		name, pattern, ok := strings.Cut(spec, ":")
		if !ok {
			return nil, fmt.Errorf("headerfilter: invalid spec %q: expected 'Header-Name: regex'", spec)
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("headerfilter: invalid spec %q: empty header name", spec)
		}
		// A regex rarely intends to depend on the leading shell-quoting space
		// after the colon; trim it like matchheaders does for --match-headers.
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			return nil, fmt.Errorf("headerfilter: invalid spec %q: empty regex for header %q", spec, name)
		}

		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("headerfilter: invalid regex %q for header %q: %w", pattern, name, err)
		}

		f.rules = append(f.rules, headerRule{
			name: textproto.CanonicalMIMEHeaderKey(name),
			re:   re,
		})
	}
	return f, nil
}

// Active reports whether the filter has any rules. When false, Match always
// returns false (suppress nothing) and callers can skip the check entirely.
func (f *Filter) Active() bool {
	return f != nil && len(f.rules) > 0
}

// Match reports whether a response carrying the given headers should be
// suppressed (filtered). A response is suppressed if ANY rule matches: the named
// header is present and at least one of its values matches the rule's regex. An
// inactive filter suppresses nothing, returning false. A nil header map matches
// no rule, so an active filter keeps it.
func (f *Filter) Match(h http.Header) bool {
	if !f.Active() {
		return false
	}
	for _, rule := range f.rules {
		if ruleMatches(rule, h) {
			return true
		}
	}
	return false
}

// ruleMatches reports whether the named header is present in h and at least one
// of its values matches the rule's regex. http.Header lookups are
// case-insensitive when the key is canonicalised, which Parse guarantees.
func ruleMatches(rule headerRule, h http.Header) bool {
	if h == nil {
		return false
	}
	for _, v := range h[rule.name] {
		if rule.re.MatchString(v) {
			return true
		}
	}
	return false
}
