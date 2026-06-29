// Test for round 14 STEP 1 — symlink resolution BEFORE path validation.
//
// Verifies that the testbed server cannot be tricked into reading files
// outside testbed/fakeroot/ via a symlink planted INSIDE the fakeroot.
//
// Pre-fix bug: filepath.Clean + HasPrefix normalizes "../" but does NOT
// resolve symlinks. A symlink at /tmp/fakeroot/leak -> /etc/passwd would
// pass containment check, then os.ReadFile would follow the symlink.
//
// Post-fix: filepath.EvalSymlinks resolves the symlink BEFORE the
// containment check; symlinks pointing outside the fakeroot now produce
// a 403 Forbidden.
package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestServer creates a Server backed by a temp directory containing a
// fixture file and an "escape" symlink pointing outside the sandbox.
func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()

	// Create a sandbox dir with one fixture file and one escape symlink.
	sandbox := t.TempDir()
	if err := os.WriteFile(filepath.Join(sandbox, "ok.txt"), []byte("in-sandbox"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// The escape symlink: a file inside the sandbox that resolves to
	// something outside (the parent temp dir).
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("SECRET-HOST-FILE"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(sandbox, "leak")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	absRoot, err := filepath.Abs(sandbox)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	s := &Server{fakeroot: sandbox, absRoot: absRoot}
	return s, sandbox
}

// TestServeFile_SymlinkEscapeBlocked is the regression test for the
// round 14 symlink-resolution fix.
func TestServeFile_SymlinkEscapeBlocked(t *testing.T) {
	s, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/?file=leak", nil)
	rr := httptest.NewRecorder()
	s.handleQuery(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for symlink escape, got %d body=%q",
			rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "SECRET-HOST-FILE") {
		t.Fatalf("HOST FILE LEAKED: response body = %q", rr.Body.String())
	}
}

// TestServeFile_LegitimateFileStillWorks is the positive-path companion
// to TestServeFile_SymlinkEscapeBlocked.
func TestServeFile_LegitimateFileStillWorks(t *testing.T) {
	s, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/?file=ok.txt", nil)
	rr := httptest.NewRecorder()
	s.handleQuery(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for legitimate file, got %d body=%q",
			rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "in-sandbox" {
		t.Fatalf("expected body 'in-sandbox', got %q", rr.Body.String())
	}
}

// TestServeFile_TraversalStillBlocked ensures the original traversal
// protection still works after the symlink fix.
func TestServeFile_TraversalStillBlocked(t *testing.T) {
	s, sandbox := newTestServer(t)

	// Create a file OUTSIDE the sandbox to attempt to read.
	outsideFile := filepath.Join(filepath.Dir(sandbox), "outside.txt")
	if err := os.WriteFile(outsideFile, []byte("OUTSIDE"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/?file=../outside.txt", nil)
	rr := httptest.NewRecorder()
	s.handleQuery(rr, req)

	if rr.Code == http.StatusOK && strings.Contains(rr.Body.String(), "OUTSIDE") {
		t.Fatalf("TRAVERSAL ESCAPED: response body = %q", rr.Body.String())
	}
}