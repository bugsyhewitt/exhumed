// Package matchheaders parses one or more response-header "require" specs and
// decides whether a given response should be KEPT (reported) because its headers
// match.
//
// matchheaders extends the positive keep-gate family
// (matchfilter/--match-regex, matchcode/--match-code, matchsize/--match-size,
// matchtime/--match-time, matchwords/--match-words) to a surface none of them
// touch: the response *headers*. Where --match-regex inspects the body and
// --match-code inspects the status line, --match-headers inspects the header
// block — the place a server quietly reveals what it actually did with a leaked
// include. When an LFI payload causes the target to read and serve a real file,
// the response headers frequently shift in ways the body does not: a sniffed
// Content-Type flips from text/html to text/plain or application/octet-stream, a
// Content-Disposition: attachment appears, an X-Powered-By or Server banner
// changes, a Set-Cookie shows up. --match-headers lets the operator name those
// distinctive headers and keep only the responses that carry them, dropping the
// uniform soft-404/WAF block pages whose body, size, word count, and status are
// all indistinguishable from the noise but whose header block is not.
//
// There is no single ffuf flag for this; ffuf's matchers are body/status/size/
// word/line oriented. --match-headers is the header-surface complement that
// rounds out the family for the LFI use case.
//
// Spec model: the flag is repeatable. Each occurrence is one
// "Header-Name: regex" pair:
//
//	--match-headers 'Content-Type: text/(plain|x-php)'
//	--match-headers 'Content-Disposition: attachment'
//	--match-headers 'X-Powered-By: PHP'
//
// Header-Name matching is case-insensitive (HTTP header names are
// case-insensitive and Go canonicalises them). The regex is a Go (RE2)
// "contains" match against each value of that header; the pair is satisfied if
// the named header is present AND at least one of its values matches. A header
// that is absent never satisfies its pair.
//
// When more than one pair is supplied they compose as a CONJUNCTION: every pair
// must be satisfied for the response to be kept. This mirrors the conjunction
// semantics of the rest of the match family (every match gate must pass).
//
// An empty spec set yields a Filter that keeps everything (Active() == false),
// so the scan output is unchanged. A malformed pair — missing colon, empty
// header name, or a regex that fails to compile — is rejected at parse time so
// the operator learns immediately rather than silently keeping nothing.
//
// This NEVER touches confirmed hits. Confirmation in exhumed is content-based
// (see internal/detect): a body that satisfies an entry's confirm block is a hit
// regardless of its headers. matchheaders only governs the unconfirmed
// "[responded]" stream, turning it from "everything that responded" into "only
// the responses whose headers look interesting."
package matchheaders

import (
	"fmt"
	"net/http"
	"net/textproto"
	"regexp"
	"strings"
)

// headerRule is one "Header-Name: regex" requirement. name is stored in the
// canonical MIME header form so lookups against an http.Header are
// case-insensitive.
type headerRule struct {
	name string
	re   *regexp.Regexp
}

// Filter decides whether a response should be kept (reported) because its
// headers satisfy every require rule. The zero value is inactive (keeps
// everything) and is safe to use.
type Filter struct {
	rules []headerRule
}

// Parse builds a Filter from a slice of "Header-Name: regex" specs (typically
// one per repeated --match-headers flag). An empty slice — or a slice whose
// entries are all blank — returns an inactive Filter and no error; callers treat
// an inactive filter as "keep everything." A malformed pair returns an error so
// the operator learns immediately rather than silently keeping nothing.
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
			return nil, fmt.Errorf("matchheaders: invalid spec %q: expected 'Header-Name: regex'", spec)
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("matchheaders: invalid spec %q: empty header name", spec)
		}
		// A regex rarely intends to depend on the leading shell-quoting space
		// after the colon; trim it like matchfilter does for --match-regex.
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			return nil, fmt.Errorf("matchheaders: invalid spec %q: empty regex for header %q", spec, name)
		}

		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("matchheaders: invalid regex %q for header %q: %w", pattern, name, err)
		}

		f.rules = append(f.rules, headerRule{
			name: textproto.CanonicalMIMEHeaderKey(name),
			re:   re,
		})
	}
	return f, nil
}

// Active reports whether the filter has any rules. When false, Keep always
// returns true (keep everything) and callers can skip the check entirely.
func (f *Filter) Active() bool {
	return f != nil && len(f.rules) > 0
}

// Keep reports whether a response carrying the given headers should be kept
// (reported). Every rule must be satisfied: the named header must be present and
// at least one of its values must match the rule's regex. An inactive filter
// keeps everything, returning true. A nil header map satisfies no rule, so an
// active filter drops it.
func (f *Filter) Keep(h http.Header) bool {
	if !f.Active() {
		return true
	}
	for _, rule := range f.rules {
		if !ruleMatches(rule, h) {
			return false
		}
	}
	return true
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
