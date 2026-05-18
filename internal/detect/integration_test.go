package detect_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bugsyhewitt/exhumed/internal/db"
	"github.com/bugsyhewitt/exhumed/internal/detect"
	"github.com/bugsyhewitt/exhumed/internal/engine"
)

// fakerootServer creates an httptest.Server that serves files from
// testbed/fakeroot, mirroring the real testbed server behaviour.
func fakerootServer(t *testing.T) *httptest.Server {
	t.Helper()
	// Walk up from this file's directory to find the repo root.
	root := findFakeroot(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("file")
		if path == "" {
			http.Error(w, "missing file param", http.StatusBadRequest)
			return
		}
		clean := filepath.Join(root, filepath.Clean("/"+path))
		if !strings.HasPrefix(clean, root+string(os.PathSeparator)) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		data, err := os.ReadFile(clean)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(data)
	}))
	return srv
}

func findFakeroot(t *testing.T) string {
	t.Helper()
	// This test is at internal/detect/; fakeroot is at testbed/fakeroot/ from repo root.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// Walk up until we find testbed/fakeroot.
	for {
		candidate := filepath.Join(dir, "testbed", "fakeroot")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			abs, _ := filepath.Abs(candidate)
			return abs
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find testbed/fakeroot from test directory")
		}
		dir = parent
	}
}

// fetchFile uses the given test server to GET a file and returns an engine.Result.
func fetchFile(srv *httptest.Server, path string) (engine.Result, error) {
	resp, err := http.Get(srv.URL + "/?file=" + path)
	if err != nil {
		return engine.Result{}, err
	}
	defer resp.Body.Close()
	var buf []byte
	buf = make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	return engine.Result{
		StatusCode: resp.StatusCode,
		Body:       buf,
		Headers:    http.Header(resp.Header),
	}, nil
}

// TestScanE2E_PasswdConfirmed verifies that the testbed's /etc/passwd fixture
// triggers the etc-passwd confirm pattern.
func TestScanE2E_PasswdConfirmed(t *testing.T) {
	srv := fakerootServer(t)
	defer srv.Close()

	entry := makeEntry(db.ConfirmTypeRegex, []string{`root:.*:0:0:`}, nil, 0)

	result, err := fetchFile(srv, "etc/passwd")
	if err != nil {
		t.Fatalf("fetch etc/passwd: %v", err)
	}
	d := detect.Check(entry, result)
	if !d.Hit {
		t.Errorf("expected etc-passwd to be confirmed; body=%q confidence=%q",
			string(result.Body), d.Confidence)
	}
}

// TestScanE2E_WpConfigConfirmed verifies wp-config.php triggers DB_PASSWORD confirm.
func TestScanE2E_WpConfigConfirmed(t *testing.T) {
	srv := fakerootServer(t)
	defer srv.Close()

	entry := makeEntry(db.ConfirmTypeRegex, []string{`DB_PASSWORD`}, nil, 0)
	result, err := fetchFile(srv, "app/wp-config.php")
	if err != nil {
		t.Fatalf("fetch wp-config.php: %v", err)
	}
	d := detect.Check(entry, result)
	if !d.Hit {
		t.Errorf("expected wp-config.php to be confirmed; body=%q", string(result.Body))
	}
}

// TestScanE2E_ProcEnvironConfirmed verifies /proc/self/environ fixture triggers PATH= confirm.
func TestScanE2E_ProcEnvironConfirmed(t *testing.T) {
	srv := fakerootServer(t)
	defer srv.Close()

	entry := makeEntry(db.ConfirmTypeKeyword, []string{`PATH=`}, nil, 0)
	result, err := fetchFile(srv, "proc/self/environ")
	if err != nil {
		t.Fatalf("fetch proc/self/environ: %v", err)
	}
	d := detect.Check(entry, result)
	if !d.Hit {
		t.Errorf("expected proc/self/environ to be confirmed; body=%q", string(result.Body))
	}
}

// TestScanE2E_NginxConfirmed verifies nginx.conf triggers the nginx confirm pattern.
func TestScanE2E_NginxConfirmed(t *testing.T) {
	srv := fakerootServer(t)
	defer srv.Close()

	entry := makeEntry(db.ConfirmTypeKeyword, []string{`worker_processes`}, nil, 0)
	result, err := fetchFile(srv, "etc/nginx.conf")
	if err != nil {
		t.Fatalf("fetch nginx.conf: %v", err)
	}
	d := detect.Check(entry, result)
	if !d.Hit {
		t.Errorf("expected nginx.conf to be confirmed; body=%q", string(result.Body))
	}
}

// TestScanE2E_DecoyNotConfirmed verifies the error-decoy file is NOT confirmed
// as a positive hit, proving the detector is confirm-aware not just status-aware.
func TestScanE2E_DecoyNotConfirmed(t *testing.T) {
	srv := fakerootServer(t)
	defer srv.Close()

	// The decoy returns 200 with PHP-error content that echoes the path.
	// Even though it contains the text "/etc/passwd", the confirm pattern
	// root:.*:0:0: does NOT appear, so it must not be a confirmed hit.
	entry := makeEntry(db.ConfirmTypeRegex, []string{`root:.*:0:0:`}, nil, 0)
	result, err := fetchFile(srv, "etc/error-decoy")
	if err != nil {
		t.Fatalf("fetch error-decoy: %v", err)
	}
	if result.StatusCode != 200 {
		t.Skipf("decoy file not found in fakeroot (status %d) — add testbed/fakeroot/etc/error-decoy", result.StatusCode)
	}
	d := detect.Check(entry, result)
	if d.Hit {
		t.Errorf("decoy file should NOT be confirmed; got Hit=true, snippets=%v", d.Snippets)
	}
}

// TestScanE2E_NegateOnDecoy verifies that a negate pattern suppresses a match.
// Uses the decoy file which contains PHP error text.
func TestScanE2E_NegateOnDecoy(t *testing.T) {
	srv := fakerootServer(t)
	defer srv.Close()

	// The decoy contains "No such file or directory" — use that as negate.
	// Pattern matches a word present in decoy; negate should suppress.
	entry := makeEntry(db.ConfirmTypeRegex,
		[]string{`failed to open stream`}, // will match the decoy
		[]string{`(?i)no such file`},      // negate: also in decoy → should suppress
		0)
	result, err := fetchFile(srv, "etc/error-decoy")
	if err != nil {
		t.Fatalf("fetch error-decoy: %v", err)
	}
	if result.StatusCode != 200 {
		t.Skipf("decoy file not found (status %d)", result.StatusCode)
	}
	d := detect.Check(entry, result)
	if d.Hit {
		t.Errorf("negate should have suppressed the match on error-decoy; Hit=true, snippets=%v", d.Snippets)
	}
}
