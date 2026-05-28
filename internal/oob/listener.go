package oob

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Interaction is a single observed out-of-band callback recorded by the
// built-in listener. It is the correlation counterpart to a generated Payload:
// when a blind-LFI sink fires against an http(s) OOB payload pointed at the
// listener, the resulting HTTP request is captured here, proving the sink read
// and dereferenced the attacker-controlled resource even though the target's
// own HTTP response reflected nothing.
type Interaction struct {
	// Seq is a monotonic 1-based sequence number assigned on receipt.
	Seq int `json:"seq"`
	// At is the wall-clock time the interaction was observed.
	At time.Time `json:"at"`
	// RemoteIP is the source address of the callback (the target's egress IP).
	RemoteIP string `json:"remote_ip"`
	// Host is the Host header sent by the caller; for label-mode payloads its
	// leading subdomain attributes the hit to a technique.
	Host string `json:"host"`
	// Method is the HTTP method of the callback.
	Method string `json:"method"`
	// Path is the request path (the OOB payload's resource path).
	Path string `json:"path"`
	// UserAgent is the caller's User-Agent, if any (often identifies the sink:
	// PHP, Java URLConnection, libcurl, etc.).
	UserAgent string `json:"user_agent,omitempty"`
	// Technique is the OOB class this interaction is attributed to, inferred
	// from the Host header's leading label (see labelFor). Empty when the host
	// carries no recognised technique label.
	Technique Technique `json:"technique,omitempty"`
}

// techniqueFromHost infers the OOB technique from a Host header by matching its
// leading subdomain label against the labels Generate emits in label mode. It
// strips any port and lowercases before matching. Returns the empty Technique
// when no recognised label is present (e.g. the payload was generated without
// --label, or the host is a bare IP).
func techniqueFromHost(host string) Technique {
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSpace(host))
	label := host
	if i := strings.IndexByte(host, '.'); i >= 0 {
		label = host[:i]
	}
	switch label {
	case "smb":
		return TechniqueSMB
	case "http":
		return TechniqueHTTP
	case "https":
		return TechniqueHTTPS
	case "dns":
		return TechniqueDNS
	}
	return ""
}

// Listener is a self-contained HTTP collaborator that records OOB interactions.
// It runs entirely in-process over net/http — no cgo, no external collaborator
// service, no outbound network I/O — so it preserves exhumed's static-binary
// constraint and works for local and lab testing where the operator controls
// DNS or points payloads straight at the listener's address.
//
// A Listener is safe for concurrent use: HTTP handlers append interactions
// under a mutex, and Interactions returns a copied snapshot.
type Listener struct {
	mu           sync.Mutex
	interactions []Interaction

	// onInteraction, if set, is called (outside the lock) after each
	// interaction is recorded, enabling live streaming to the operator.
	onInteraction func(Interaction)
}

// NewListener returns an empty Listener. onInteraction may be nil; when set it
// is invoked with each interaction as it arrives (after the interaction has
// been recorded), letting callers stream hits live.
func NewListener(onInteraction func(Interaction)) *Listener {
	return &Listener{onInteraction: onInteraction}
}

// ServeHTTP records every incoming request as an Interaction and replies with a
// fixed, minimal body. Recording happens for all methods and paths so any sink
// behaviour (HEAD probes, GET fetches, POST writes) is captured.
func (l *Listener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Drain and discard the body so keep-alive connections are reusable and the
	// caller does not block on an unread body.
	if r.Body != nil {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}

	ip := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = h
	}

	l.mu.Lock()
	in := Interaction{
		Seq:       len(l.interactions) + 1,
		At:        time.Now().UTC(),
		RemoteIP:  ip,
		Host:      r.Host,
		Method:    r.Method,
		Path:      r.URL.Path,
		UserAgent: r.UserAgent(),
		Technique: techniqueFromHost(r.Host),
	}
	l.interactions = append(l.interactions, in)
	l.mu.Unlock()

	if l.onInteraction != nil {
		l.onInteraction(in)
	}

	// A deterministic body lets an operator eyeball that the listener — not the
	// target's own app — answered the fetch.
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Server", "exhumed-oob")
	_, _ = io.WriteString(w, "exhumed-oob\n")
}

// Interactions returns a snapshot copy of all interactions recorded so far, in
// receipt order. The returned slice is independent of the Listener's internal
// state and safe to retain or mutate.
func (l *Listener) Interactions() []Interaction {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Interaction, len(l.interactions))
	copy(out, l.interactions)
	return out
}

// Count returns the number of interactions recorded so far.
func (l *Listener) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.interactions)
}

// MarshalJSON renders the recorded interactions as a JSON array, suitable for
// piping the listener's findings into other tooling.
func (l *Listener) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.Interactions())
}

// Serve binds an HTTP server to addr and serves until ctx is cancelled, after
// which it shuts the server down gracefully. addr is a standard host:port
// string (e.g. "0.0.0.0:8080" or ":8080"). The bound address — useful when the
// caller passes ":0" for an OS-assigned port — is reported via onReady (which
// may be nil) before serving begins.
//
// Serve returns nil on a clean ctx-driven shutdown, or a non-nil error if the
// listener could not bind or the server failed for any reason other than the
// expected http.ErrServerClosed.
func (l *Listener) Serve(ctx context.Context, addr string, onReady func(boundAddr string)) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("bind %s: %w", addr, err)
	}

	srv := &http.Server{
		Handler:           l,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if onReady != nil {
		onReady(ln.Addr().String())
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		// Graceful shutdown with a bounded deadline so a wedged connection
		// cannot hang exit indefinitely.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
