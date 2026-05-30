// Package replay sends a copy of a confirmed-hit request through a separate
// HTTP proxy so an operator can pick the request up in an interception tool
// (Burp Suite, OWASP ZAP, mitmproxy, Caido) for manual triage and exploitation.
//
// replay is the response-side companion to engine's --proxy. Where --proxy
// routes every scan request through a proxy (noisy at high concurrency and
// drowns the operator in soft-404/WAF noise), --replay-proxy sends only the
// requests that confirmed a hit. After detect.Check reports Hit=true on a
// payload, the same engine.Request that produced the hit is re-issued through
// the replay client; the response is intentionally discarded — the replay's
// purpose is to populate the operator's intercepting proxy's HTTP history with
// the precise byte sequence that worked, not to re-confirm the finding.
//
// This is the ffuf -replay-proxy / -p (replay-proxy) workflow and the most-
// requested missing matcher/output flag in the family. ffuf's docs:
// "replay-proxy URL of the proxy that the matched requests are sent to".
// exhumed mirrors that semantic exactly: only matched (confirmed) requests are
// replayed.
//
// Design constraints:
//
//   - Out-of-band: a replay error NEVER fails the scan. The original hit was
//     already confirmed by the scan engine; the replay is a courtesy I/O so a
//     transient proxy-unreachable, a TLS handshake error, or a timeout against
//     the replay proxy is logged (when verbose) and otherwise silent.
//   - Separate client: the replay uses its own *http.Client with its own
//     *http.Transport so its proxy URL, TLS verification choice, keep-alive
//     pool, and timeout are independent of the scan engine. In particular, the
//     scan engine's --proxy and --insecure settings do NOT bleed into the
//     replay path.
//   - Best-effort body capture: replay reads (and discards) the response body
//     up to a small cap so the connection can be returned to the pool. The
//     body bytes are never surfaced.
//   - No redirect following: the replay path mirrors the scan engine's
//     redirect policy — a 3xx is returned verbatim so the operator's proxy
//     sees the exact response the scan saw.
//   - Pure-Go stdlib: net/http, net/url, crypto/tls, io, time. No new
//     dependencies, no cgo. MIT-clean per the project's license constraint.
//
// Spec model: --replay-proxy takes a single URL. The scheme must be http,
// https, socks5, or socks5h (the schemes net/http's transport-proxy accepts).
// Parse validates the URL up front so a malformed spec fails before any
// requests fire — consistent with the rest of the flag family's "validate at
// parse, never silently no-op" contract.
//
// An inactive client (Parse on an empty/whitespace spec) is a no-op: Replay
// returns nil without making a request. This keeps the call site in scan.go
// trivial — no flag-active branch needed at every hit.
package replay

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bugsyhewitt/exhumed/internal/engine"
)

// maxDiscardBody caps the response body read on a replay so the connection can
// be returned to the keep-alive pool without holding a multi-MB read open. The
// body bytes are never surfaced; this is purely about pool hygiene.
const maxDiscardBody int64 = 64 * 1024

// validSchemes enumerates the proxy URL schemes net/http's transport-proxy
// helper accepts. Anything else is rejected at Parse so the operator learns
// immediately rather than silently failing on every hit.
var validSchemes = map[string]bool{
	"http":    true,
	"https":   true,
	"socks5":  true,
	"socks5h": true,
}

// Client wraps a stdlib *http.Client configured to send requests through a
// single replay proxy. The zero value is the inactive client (Replay no-op).
type Client struct {
	client   *http.Client
	proxyURL string // canonical form for diagnostics; empty when inactive
	active   bool
}

// Parse validates spec (a proxy URL or the empty string) and returns a Client.
//
// An empty or whitespace-only spec yields an inactive Client whose Replay is a
// no-op — the call site can unconditionally invoke Replay without a flag-active
// branch.
//
// timeout caps each replay request (per-request, like the scan engine's
// --timeout). insecure controls TLS certificate verification on the replay
// path; it is independent of the scan engine's --insecure so an operator can
// scan a public target without TLS skip yet replay through a self-signed
// Burp/ZAP listener.
//
// A malformed URL, a missing scheme, an unknown scheme, or a missing host is
// rejected here so a typo never silently routes hits to /dev/null.
func Parse(spec string, timeout time.Duration, insecure bool) (*Client, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return &Client{}, nil
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("replay-proxy: parse %q: %w", trimmed, err)
	}
	if u.Scheme == "" {
		return nil, fmt.Errorf("replay-proxy: %q: missing scheme (expected http, https, socks5, or socks5h)", trimmed)
	}
	scheme := strings.ToLower(u.Scheme)
	if !validSchemes[scheme] {
		return nil, fmt.Errorf("replay-proxy: %q: unsupported scheme %q (expected http, https, socks5, or socks5h)", trimmed, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("replay-proxy: %q: missing host", trimmed)
	}

	transport := &http.Transport{
		Proxy:               http.ProxyURL(u),
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec
		DisableKeepAlives:   false,
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 2,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// Mirror the scan engine: do NOT follow redirects so the operator's
		// proxy sees the exact 3xx response the scan saw, not the redirect
		// target's response.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Client{
		client:   httpClient,
		proxyURL: u.String(),
		active:   true,
	}, nil
}

// Active reports whether this Client will actually send replay requests.
// An inactive Client (constructed from an empty spec) returns false; its
// Replay is a no-op. Use this for diagnostics — Replay does its own active
// check, so the caller does not need to gate the call.
func (c *Client) Active() bool {
	if c == nil {
		return false
	}
	return c.active
}

// ProxyURL returns the canonical proxy URL string for diagnostics. Empty
// when inactive.
func (c *Client) ProxyURL() string {
	if c == nil {
		return ""
	}
	return c.proxyURL
}

// Replay sends req through the configured proxy and discards the response.
//
// An inactive Client (or a nil receiver) returns nil immediately without
// issuing a request — the call site can invoke Replay unconditionally.
//
// The response body is read (up to maxDiscardBody) and discarded so the
// underlying connection can be returned to the keep-alive pool. The status
// code, headers, and body are intentionally not surfaced: the replay's purpose
// is to populate an interception proxy's HTTP history, not to re-confirm a
// finding the scan engine has already confirmed.
//
// Returned errors are advisory only — the caller (scan.go) should log them
// when --verbose is set but MUST NOT fail the scan on a replay error. A replay
// failure means "the operator's Burp didn't see this hit", not "the hit
// didn't happen".
//
// Cancelling ctx aborts the replay.
func (c *Client) Replay(ctx context.Context, req engine.Request) error {
	if c == nil || !c.active {
		return nil
	}

	method := req.Method
	if method == "" {
		method = http.MethodGet
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return fmt.Errorf("replay: build request: %w", err)
	}

	for key, vals := range req.Headers {
		for _, v := range vals {
			httpReq.Header.Add(key, v)
		}
	}
	for name, val := range req.Cookies {
		httpReq.AddCookie(&http.Cookie{Name: name, Value: val})
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("replay via %s: %w", c.proxyURL, err)
	}
	defer resp.Body.Close()

	// Drain so the connection returns to the keep-alive pool. Discard bytes —
	// the replay's purpose is to populate the operator's interception proxy,
	// not to surface response content.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDiscardBody))
	return nil
}
