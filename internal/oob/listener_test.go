package oob

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTechniqueFromHost(t *testing.T) {
	cases := []struct {
		host string
		want Technique
	}{
		{"smb.abc123.oast.fun", TechniqueSMB},
		{"http.abc123.oast.fun", TechniqueHTTP},
		{"https.abc123.oast.fun", TechniqueHTTPS},
		{"dns.abc123.oast.fun", TechniqueDNS},
		{"HTTP.ABC123.OAST.FUN", TechniqueHTTP},      // case-insensitive
		{"http.abc123.oast.fun:8080", TechniqueHTTP}, // port stripped
		{"abc123.oast.fun", ""},                      // no label
		{"192.0.2.10", ""},                           // bare IP
		{"", ""},                                     // empty
		{"unknownlabel.example.com", ""},             // unrecognised label
	}
	for _, tc := range cases {
		if got := techniqueFromHost(tc.host); got != tc.want {
			t.Errorf("techniqueFromHost(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

func TestListener_RecordsInteraction(t *testing.T) {
	l := NewListener(nil)
	srv := httptest.NewServer(l)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/exhumed-oob", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// Simulate a label-mode payload by overriding the Host header.
	req.Host = "http.abc123.oast.fun"
	req.Header.Set("User-Agent", "PHP/8.2")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if !strings.Contains(string(body), "exhumed-oob") {
		t.Errorf("body = %q, want listener marker", string(body))
	}
	if got := resp.Header.Get("Server"); got != "exhumed-oob" {
		t.Errorf("Server header = %q, want exhumed-oob", got)
	}

	got := l.Interactions()
	if len(got) != 1 {
		t.Fatalf("recorded %d interactions, want 1", len(got))
	}
	in := got[0]
	if in.Seq != 1 {
		t.Errorf("Seq = %d, want 1", in.Seq)
	}
	if in.Method != http.MethodGet {
		t.Errorf("Method = %q, want GET", in.Method)
	}
	if in.Path != "/exhumed-oob" {
		t.Errorf("Path = %q, want /exhumed-oob", in.Path)
	}
	if in.Host != "http.abc123.oast.fun" {
		t.Errorf("Host = %q", in.Host)
	}
	if in.Technique != TechniqueHTTP {
		t.Errorf("Technique = %q, want %q (from host label)", in.Technique, TechniqueHTTP)
	}
	if in.UserAgent != "PHP/8.2" {
		t.Errorf("UserAgent = %q", in.UserAgent)
	}
	if in.RemoteIP == "" {
		t.Error("RemoteIP is empty")
	}
	if in.At.IsZero() {
		t.Error("At is zero")
	}
}

func TestListener_SequenceAndCount(t *testing.T) {
	l := NewListener(nil)
	srv := httptest.NewServer(l)
	defer srv.Close()

	const n = 5
	for i := 0; i < n; i++ {
		resp, err := http.Get(srv.URL + "/beacon")
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	if got := l.Count(); got != n {
		t.Fatalf("Count = %d, want %d", got, n)
	}
	got := l.Interactions()
	for i, in := range got {
		if in.Seq != i+1 {
			t.Errorf("interaction %d Seq = %d, want %d", i, in.Seq, i+1)
		}
	}
}

func TestListener_OnInteractionCallback(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []Interaction
	)
	l := NewListener(func(in Interaction) {
		mu.Lock()
		seen = append(seen, in)
		mu.Unlock()
	})
	srv := httptest.NewServer(l)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 {
		t.Fatalf("callback fired %d times, want 1", len(seen))
	}
	if seen[0].Path != "/x" {
		t.Errorf("callback interaction Path = %q, want /x", seen[0].Path)
	}
}

func TestListener_InteractionsSnapshotIsCopy(t *testing.T) {
	l := NewListener(nil)
	srv := httptest.NewServer(l)
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/a")
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	snap := l.Interactions()
	if len(snap) != 1 {
		t.Fatalf("snapshot len = %d, want 1", len(snap))
	}
	// Mutating the snapshot must not affect a later snapshot.
	snap[0].Path = "MUTATED"

	resp2, _ := http.Get(srv.URL + "/b")
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()

	snap2 := l.Interactions()
	if len(snap2) != 2 {
		t.Fatalf("second snapshot len = %d, want 2", len(snap2))
	}
	if snap2[0].Path != "/a" {
		t.Errorf("snapshot mutation leaked: Path = %q, want /a", snap2[0].Path)
	}
}

func TestListener_MarshalJSON(t *testing.T) {
	l := NewListener(nil)
	srv := httptest.NewServer(l)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/p", strings.NewReader("blob"))
	req.Host = "dns.c.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	data, err := json.Marshal(l)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded []Interaction
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("decoded %d, want 1", len(decoded))
	}
	if decoded[0].Technique != TechniqueDNS {
		t.Errorf("decoded technique = %q, want %q", decoded[0].Technique, TechniqueDNS)
	}
	if decoded[0].Method != http.MethodPost {
		t.Errorf("decoded method = %q, want POST", decoded[0].Method)
	}
}

func TestListener_ServeBindsAndShutsDown(t *testing.T) {
	l := NewListener(nil)
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
		t.Fatal("listener did not become ready")
	}

	resp, err := http.Get("http://" + addr + "/probe")
	if err != nil {
		t.Fatalf("get against bound listener: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if got := l.Count(); got != 1 {
		t.Errorf("Count = %d, want 1", got)
	}

	cancel()
	select {
	case err := <-doneCh:
		if err != nil {
			t.Errorf("Serve returned error on clean shutdown: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("Serve did not return after ctx cancel")
	}
}

func TestListener_ServeBindError(t *testing.T) {
	l := NewListener(nil)
	// An obviously invalid address should fail to bind quickly.
	err := l.Serve(context.Background(), "256.256.256.256:99999", nil)
	if err == nil {
		t.Error("expected bind error for invalid address, got nil")
	}
}
