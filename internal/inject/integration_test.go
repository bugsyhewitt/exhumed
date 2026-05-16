// Package inject — integration test that drives engine + inject against a
// real HTTP server (the testbed server pattern) to verify the full pipeline.
package inject

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bugsyhewitt/exhumed/internal/engine"
)

// miniTestbed is a minimal LFI-simulation server for integration testing.
// It reads files from a temp fakeroot — it does NOT read real host files.
type miniTestbed struct {
	absRoot string
}

func newMiniTestbed(t *testing.T) (*miniTestbed, string) {
	t.Helper()

	// Create a temp directory as the fakeroot.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"),
		[]byte("root:x:0:0:root:/root:/bin/bash\n"), 0o644); err != nil {
		t.Fatalf("writefile: %v", err)
	}

	return &miniTestbed{absRoot: root}, root
}

func (m *miniTestbed) serveFile(w http.ResponseWriter, userPath string) {
	if userPath == "" {
		http.Error(w, "missing path", http.StatusBadRequest)
		return
	}
	cleaned := filepath.Join(m.absRoot, filepath.Clean("/"+userPath))
	if !strings.HasPrefix(cleaned, m.absRoot+string(os.PathSeparator)) && cleaned != m.absRoot {
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}
	data, err := os.ReadFile(cleaned)
	if err != nil {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(data)
}

func (m *miniTestbed) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/", "":
		m.serveFile(w, r.URL.Query().Get("file"))
	case "/load":
		r.ParseForm() //nolint:errcheck
		m.serveFile(w, r.FormValue("path"))
	case "/header":
		m.serveFile(w, r.Header.Get("X-Include-File"))
	case "/cookie":
		c, err := r.Cookie("lfi_path")
		if err != nil {
			http.Error(w, "missing cookie", http.StatusBadRequest)
			return
		}
		m.serveFile(w, c.Value)
	case "/json":
		var req struct {
			Path string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		m.serveFile(w, req.Path)
	default:
		http.NotFound(w, r)
	}
}

// startServer starts the testbed on a random free port and returns the base URL.
func startServer(t *testing.T, h http.Handler) (baseURL string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln) //nolint:errcheck
	return fmt.Sprintf("http://%s", ln.Addr().String()), func() { srv.Close() }
}

func waitReady(t *testing.T, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/?file=etc/passwd")
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server did not become ready within 3 seconds")
}

// TestIntegration_QuerySurface drives the full engine+inject pipeline against
// the query-parameter surface of the mini testbed.
func TestIntegration_QuerySurface(t *testing.T) {
	tb, _ := newMiniTestbed(t)
	base, stop := startServer(t, tb)
	defer stop()
	waitReady(t, base)

	tmpl := NewRequest("GET", base+"/?file=FUZZ")

	req := Substitute(tmpl, "FUZZ", "etc/passwd")

	eng := engine.New(engine.Config{
		Concurrency: 1,
		Timeout:     5 * time.Second,
	})

	results := eng.Run(context.Background(), []engine.Request{req})

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Err != nil {
		t.Fatalf("request error: %v", r.Err)
	}
	if r.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", r.StatusCode)
	}
	if len(r.Body) == 0 {
		t.Error("expected non-empty body")
	}
	if !strings.Contains(string(r.Body), "root") {
		t.Errorf("body should contain passwd content, got: %s", r.Body)
	}
}

// TestIntegration_HeaderSurface verifies injection via the X-Include-File header.
func TestIntegration_HeaderSurface(t *testing.T) {
	tb, _ := newMiniTestbed(t)
	base, stop := startServer(t, tb)
	defer stop()
	waitReady(t, base)

	tmpl := NewRequest("GET", base+"/header")
	tmpl.Headers.Set("X-Include-File", "FUZZ")

	req := Substitute(tmpl, "FUZZ", "etc/passwd")

	eng := engine.New(engine.Config{
		Concurrency: 1,
		Timeout:     5 * time.Second,
	})

	results := eng.Run(context.Background(), []engine.Request{req})
	r := results[0]

	if r.Err != nil {
		t.Fatalf("request error: %v", r.Err)
	}
	if r.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", r.StatusCode)
	}
	if len(r.Body) == 0 {
		t.Error("expected non-empty body")
	}
}
