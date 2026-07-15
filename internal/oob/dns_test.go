package oob

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseDNSEntryIdx(t *testing.T) {
	cases := []struct {
		name string
		want int
	}{
		{"cb-0.oob.local.", 0},
		{"cb-5.oob.local.", 5},
		{"cb-42.oob.local.", 42},
		{"cb-0.", 0},
		{"cb-99.", 99},
		{"CB-3.OOB.LOCAL.", 3},        // case-insensitive
		{"notcb.oob.local.", -1},      // wrong prefix
		{"oob.local.", -1},            // no cb- label
		{"cb-.local.", -1},            // empty index
		{"cb-abc.local.", -1},         // non-numeric index
		{"cb--1.local.", -1},          // negative (leading minus parsed as bad int after TrimPrefix)
		{".", -1},                     // root
		{"", -1},                      // empty
		{"cb-0", 0},                   // no trailing dot, no sub-domain
		{"something.cb-7.local.", -1}, // cb- label is not the first
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseDNSEntryIdx(tc.name); got != tc.want {
				t.Errorf("parseDNSEntryIdx(%q) = %d, want %d", tc.name, got, tc.want)
			}
		})
	}
}

// TestDNSListener_RecordsInteraction verifies that the DNS listener captures a
// query and records it with the correct metadata.
func TestDNSListener_RecordsInteraction(t *testing.T) {
	l := NewDNSListener(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := startDNSListener(t, l, ctx)

	sendDNSQuery(t, addr, "cb-7.oob.local.")

	// Brief pause to let the handler record the interaction before we read.
	time.Sleep(30 * time.Millisecond)

	got := l.DNSInteractions()
	if len(got) != 1 {
		t.Fatalf("recorded %d DNS interactions, want 1", len(got))
	}
	in := got[0]
	if in.Seq != 1 {
		t.Errorf("Seq = %d, want 1", in.Seq)
	}
	if in.EntryIdx != 7 {
		t.Errorf("EntryIdx = %d, want 7", in.EntryIdx)
	}
	if in.Name != "cb-7.oob.local." {
		t.Errorf("Name = %q, want cb-7.oob.local.", in.Name)
	}
	if in.Qtype == "" {
		t.Error("Qtype is empty")
	}
	if in.RemoteIP == "" {
		t.Error("RemoteIP is empty")
	}
	if in.At.IsZero() {
		t.Error("At is zero")
	}
}

// TestDNSListener_EntryIdxCorrelation verifies that each cb-<idx> query is
// correlated to the correct entry index.
func TestDNSListener_EntryIdxCorrelation(t *testing.T) {
	l := NewDNSListener(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := startDNSListener(t, l, ctx)

	indices := []int{0, 1, 99}
	for _, idx := range indices {
		sendDNSQuery(t, addr, fmt.Sprintf("cb-%d.oob.local.", idx))
	}
	time.Sleep(30 * time.Millisecond)

	got := l.DNSInteractions()
	if len(got) != len(indices) {
		t.Fatalf("got %d interactions, want %d", len(got), len(indices))
	}
	for i, in := range got {
		if in.EntryIdx != indices[i] {
			t.Errorf("interaction %d: EntryIdx = %d, want %d", i, in.EntryIdx, indices[i])
		}
	}
}

// TestDNSListener_RandomPort verifies that addr "127.0.0.1:0" causes the OS to
// assign a free port, which onReady reports before serving begins.
func TestDNSListener_RandomPort(t *testing.T) {
	l := NewDNSListener(nil)
	ctx, cancel := context.WithCancel(context.Background())

	readyCh := make(chan string, 1)
	doneCh := make(chan error, 1)
	go func() {
		doneCh <- l.Serve(ctx, "127.0.0.1:0", func(addr string) {
			readyCh <- addr
		})
	}()

	var addr string
	select {
	case addr = <-readyCh:
	case <-time.After(2 * time.Second):
		t.Fatal("DNS listener did not become ready")
	}

	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("invalid bound addr %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port == 0 {
		t.Errorf("expected non-zero OS-assigned port, got %q", portStr)
	}

	sendDNSQuery(t, addr, "cb-0.test.")
	time.Sleep(20 * time.Millisecond)
	if got := l.DNSCount(); got != 1 {
		t.Errorf("DNSCount = %d, want 1 after random-port query", got)
	}

	cancel()
	select {
	case err := <-doneCh:
		if err != nil {
			t.Errorf("Serve returned error on clean shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after ctx cancel")
	}
}

// TestDNSListener_OnInteractionCallback verifies that onInteraction fires for
// each recorded interaction.
func TestDNSListener_OnInteractionCallback(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []DNSInteraction
	)
	l := NewDNSListener(func(in DNSInteraction) {
		mu.Lock()
		seen = append(seen, in)
		mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := startDNSListener(t, l, ctx)

	sendDNSQuery(t, addr, "cb-3.oob.local.")
	time.Sleep(30 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 {
		t.Fatalf("callback fired %d times, want 1", len(seen))
	}
	if seen[0].EntryIdx != 3 {
		t.Errorf("callback EntryIdx = %d, want 3", seen[0].EntryIdx)
	}
}

// TestDNSListener_BindError verifies that an obviously invalid address is
// rejected immediately.
func TestDNSListener_BindError(t *testing.T) {
	l := NewDNSListener(nil)
	err := l.Serve(context.Background(), "256.256.256.256:99999", nil)
	if err == nil {
		t.Error("expected bind error for invalid address, got nil")
	}
}

// startDNSListener starts l in a background goroutine and returns the bound
// address once onReady fires. The goroutine is tied to ctx, which the caller
// controls via the cancel it defers.
func startDNSListener(t *testing.T, l *DNSListener, ctx context.Context) string {
	t.Helper()
	readyCh := make(chan string, 1)
	go func() {
		if err := l.Serve(ctx, "127.0.0.1:0", func(addr string) {
			readyCh <- addr
		}); err != nil {
			// Only an unexpected error (not ctx cancellation) should land here.
			t.Logf("DNSListener.Serve: %v", err)
		}
	}()
	select {
	case addr := <-readyCh:
		return addr
	case <-time.After(2 * time.Second):
		t.Fatal("DNS listener did not become ready")
		return ""
	}
}

// sendDNSQuery sends a single A-record query for name to addr (host:port) and
// waits up to 2 seconds for a reply. It is a best-effort helper: the listener
// may respond with NOERROR/no-answers, which is fine for testing.
func sendDNSQuery(t *testing.T, addr, name string) {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	if _, _, err := c.Exchange(m, addr); err != nil {
		t.Fatalf("DNS query %s → %s: %v", name, addr, err)
	}
}
