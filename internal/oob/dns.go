package oob

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNSInteraction is a single observed out-of-band DNS query recorded by the
// built-in DNS listener. It is the DNS counterpart to Interaction: when a
// blind-LFI sink resolves a hostname injected by the built-in listener
// (e.g. a UNC path whose host carries a cb-<idx> label), the DNS query is
// captured here, proving the sink attempted to dereference the payload even
// though the target's HTTP response reflected nothing.
type DNSInteraction struct {
	// Seq is a monotonic 1-based sequence number assigned on receipt.
	Seq int `json:"seq"`
	// At is the wall-clock time the query was observed.
	At time.Time `json:"at"`
	// RemoteIP is the source address of the DNS client (the target's egress IP
	// or its configured resolver).
	RemoteIP string `json:"remote_ip"`
	// Name is the queried FQDN, including the trailing dot.
	Name string `json:"name"`
	// Qtype is the DNS query type as a string, e.g. "A", "AAAA", "ANY".
	Qtype string `json:"qtype"`
	// EntryIdx is the per-entry index extracted from the leading "cb-<n>" label
	// of the queried name. It is -1 when the name does not carry a cb- label.
	// Use it to look up the originating scan entry in the oobLsnrEntries slice.
	EntryIdx int `json:"entry_idx"`
}

// DNSListener is a self-contained UDP DNS collaborator that records OOB DNS
// interactions. It answers every query with NOERROR (empty answer section) to
// avoid client timeouts. All queries are recorded regardless of zone or type;
// attribution relies on the leading "cb-<idx>" label injected into UNC scan
// payloads during --oob-listen + --oob-dns-port operation.
//
// A DNSListener is safe for concurrent use.
type DNSListener struct {
	mu            sync.Mutex
	interactions  []DNSInteraction
	onInteraction func(DNSInteraction)
}

// NewDNSListener returns an empty DNSListener. onInteraction may be nil; when
// set it is called (outside the lock) after each interaction is recorded,
// enabling live streaming to the operator.
func NewDNSListener(onInteraction func(DNSInteraction)) *DNSListener {
	return &DNSListener{onInteraction: onInteraction}
}

// ServeDNS implements dns.Handler. Every incoming query is recorded as a
// DNSInteraction and answered with a minimal NOERROR reply (no answer records)
// to prevent resolver timeouts while the interaction is logged.
func (l *DNSListener) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	remoteAddr := w.RemoteAddr().String()
	remoteIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		remoteIP = remoteAddr
	}

	var name, qtype string
	if len(r.Question) > 0 {
		q := r.Question[0]
		name = q.Name
		qtype = dns.TypeToString[q.Qtype]
		if qtype == "" {
			qtype = strconv.Itoa(int(q.Qtype))
		}
	}

	l.mu.Lock()
	in := DNSInteraction{
		Seq:      len(l.interactions) + 1,
		At:       time.Now().UTC(),
		RemoteIP: remoteIP,
		Name:     name,
		Qtype:    qtype,
		EntryIdx: parseDNSEntryIdx(name),
	}
	l.interactions = append(l.interactions, in)
	l.mu.Unlock()

	if l.onInteraction != nil {
		l.onInteraction(in)
	}

	// Respond with NOERROR / empty answer so the resolver does not time out
	// and retry (which would create duplicate interactions).
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	_ = w.WriteMsg(m)
}

// parseDNSEntryIdx extracts the per-entry index from a DNS query name whose
// first label is "cb-<n>" (dot-terminated FQDN or bare label). Returns -1
// when the first label does not match the prefix or the suffix is not a valid
// non-negative integer.
func parseDNSEntryIdx(name string) int {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if n == "" {
		return -1
	}
	label := n
	if i := strings.IndexByte(n, '.'); i >= 0 {
		label = n[:i]
	}
	if !strings.HasPrefix(label, "cb-") {
		return -1
	}
	idx, err := strconv.Atoi(strings.TrimPrefix(label, "cb-"))
	if err != nil || idx < 0 {
		return -1
	}
	return idx
}

// DNSInteractions returns a snapshot copy of all DNS interactions recorded so
// far, in receipt order. The returned slice is independent of the listener's
// internal state.
func (l *DNSListener) DNSInteractions() []DNSInteraction {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]DNSInteraction, len(l.interactions))
	copy(out, l.interactions)
	return out
}

// DNSCount returns the number of DNS interactions recorded so far.
func (l *DNSListener) DNSCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.interactions)
}

// Serve binds a UDP DNS server to addr (e.g. "127.0.0.1:5353" or
// "127.0.0.1:0" for an OS-assigned port) and serves until ctx is cancelled.
// The bound address — useful when addr uses port 0 — is reported via onReady
// (which may be nil) before serving begins.
//
// Serve returns nil on a clean ctx-driven shutdown, or a non-nil error if the
// listener could not bind or the server failed unexpectedly.
func (l *DNSListener) Serve(ctx context.Context, addr string, onReady func(boundAddr string)) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("dns bind %s: %w", addr, err)
	}

	if onReady != nil {
		onReady(pc.LocalAddr().String())
	}

	srv := &dns.Server{
		PacketConn: pc,
		Net:        "udp",
		Handler:    l,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ActivateAndServe()
	}()

	select {
	case <-ctx.Done():
		_ = srv.Shutdown()
		<-errCh // drain so the goroutine exits cleanly
		return nil
	case err := <-errCh:
		return err
	}
}
