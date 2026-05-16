// Testbed server is a deliberately-vulnerable HTTP server for local
// development and automated testing of exhumed's injection and detection
// layers. It simulates LFI across five injection surfaces against a sandboxed
// fake filesystem and CANNOT read real host files.
//
// WARNING: intentionally vulnerable — localhost dev use only.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Server holds the sandboxed file root and its absolute path.
type Server struct {
	fakeroot string
	absRoot  string
}

func main() {
	port := flag.String("port", "8080", "port to listen on (localhost only)")
	fakeroot := flag.String("fakeroot", "testbed/fakeroot", "path to sandboxed file tree")
	flag.Parse()

	absRoot, err := filepath.Abs(*fakeroot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fakeroot: %v\n", err)
		os.Exit(1)
	}

	s := &Server{
		fakeroot: *fakeroot,
		absRoot:  absRoot,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleQuery)
	mux.HandleFunc("/load", s.handleBody)
	mux.HandleFunc("/header", s.handleHeader)
	mux.HandleFunc("/cookie", s.handleCookie)
	mux.HandleFunc("/json", s.handleJSON)

	// Explicitly bind 127.0.0.1 so the server is unreachable from the network.
	ln, err := net.Listen("tcp", "127.0.0.1:"+*port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "WARNING: intentionally vulnerable — localhost dev use only.")
	fmt.Fprintf(os.Stderr, "Listening on http://127.0.0.1:%s  fakeroot=%s\n", *port, absRoot)

	if err := http.Serve(ln, mux); err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
}

// serveFile resolves userPath inside the sandboxed fakeroot and writes the
// file contents. Any attempt to escape the fakeroot via traversal sequences
// is blocked: filepath.Clean normalises the path, and the prefix check
// verifies containment.
func (s *Server) serveFile(w http.ResponseWriter, userPath string) {
	if userPath == "" {
		http.Error(w, "missing path", http.StatusBadRequest)
		return
	}

	// filepath.Clean("/" + userPath) collapses ../ sequences.
	// filepath.Join then roots it inside the fakeroot.
	cleaned := filepath.Join(s.absRoot, filepath.Clean("/"+userPath))

	// Containment check: resolved path must start with absRoot + separator.
	// Adding the separator prevents prefix collisions like /tmp/fakeroot2.
	if !strings.HasPrefix(cleaned, s.absRoot+string(os.PathSeparator)) && cleaned != s.absRoot {
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}

	data, err := os.ReadFile(cleaned)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "404 Not Found", http.StatusNotFound)
			return
		}
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(data)
}

// handleQuery serves GET /?file=<path>  (query-parameter surface).
func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.serveFile(w, r.URL.Query().Get("file"))
}

// handleBody serves POST /load with body path=<path>  (body surface).
func (s *Server) handleBody(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	s.serveFile(w, r.FormValue("path"))
}

// handleHeader serves GET /header with X-Include-File header  (header surface).
func (s *Server) handleHeader(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.serveFile(w, r.Header.Get("X-Include-File"))
}

// handleCookie serves GET /cookie with lfi_path cookie  (cookie surface).
func (s *Server) handleCookie(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c, err := r.Cookie("lfi_path")
	if err != nil {
		http.Error(w, "missing cookie", http.StatusBadRequest)
		return
	}
	s.serveFile(w, c.Value)
}

// handleJSON serves POST /json with {"path":"<path>"} body  (JSON surface).
func (s *Server) handleJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	s.serveFile(w, req.Path)
}
