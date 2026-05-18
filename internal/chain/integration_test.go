package chain_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/bugsyhewitt/exhumed/internal/chain"
	"github.com/bugsyhewitt/exhumed/internal/extract"
)

func findFakerootForChain(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		candidate := filepath.Join(dir, "testbed", "fakeroot")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			abs, _ := filepath.Abs(candidate)
			return abs
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find testbed/fakeroot")
		}
		dir = parent
	}
}

func fakerootSrv(t *testing.T) *httptest.Server {
	t.Helper()
	root := findFakerootForChain(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("file")
		if path == "" {
			http.Error(w, "missing file", http.StatusBadRequest)
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

func fetchBodyChain(srv *httptest.Server, path string) ([]byte, int, error) {
	resp, err := http.Get(srv.URL + "/?file=" + path)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	return buf, resp.StatusCode, nil
}

// TestChainE2E_PasswdToSSHKey exercises the full chain:
// 1. Read /etc/passwd → extract users
// 2. Chain generates home-dir SSH targets
// 3. Confirm the SSH fixture exists in fakeroot
func TestChainE2E_PasswdToSSHKey(t *testing.T) {
	srv := fakerootSrv(t)
	defer srv.Close()

	// Step 1: fetch passwd body.
	passwdBody, status, err := fetchBodyChain(srv, "etc/passwd")
	if err != nil || status != 200 {
		t.Fatalf("fetch passwd: err=%v status=%d", err, status)
	}

	// Verify passwd body matches the expected pattern.
	re := regexp.MustCompile(`root:.*:0:0:`)
	if !re.Match(passwdBody) {
		t.Fatalf("passwd body doesn't look like real /etc/passwd: %q", string(passwdBody))
	}

	// Step 2: extract users.
	findings := extract.Parse("unix-passwd", passwdBody, "/etc/passwd")
	var appFound bool
	for _, f := range findings {
		if f.Key == "app" {
			appFound = true
		}
	}
	if !appFound {
		t.Fatalf("user 'app' not found in passwd findings: %+v", findings)
	}

	// Step 3: chain generates SSH targets.
	q := chain.New(chain.Config{MaxDepth: 3, MaxTargets: 100})
	q.Enqueue(findings)
	targets := q.Targets()

	var idRsaTarget *chain.Target
	for i := range targets {
		if targets[i].Path == "/home/app/.ssh/id_rsa" {
			idRsaTarget = &targets[i]
			break
		}
	}
	if idRsaTarget == nil {
		t.Fatalf("/home/app/.ssh/id_rsa not generated; targets: %v", targetPaths(targets))
	}

	// Step 4: fetch the SSH key target (strip leading / for fakeroot path).
	sshPath := strings.TrimPrefix(idRsaTarget.Path, "/")
	sshBody, sshStatus, err := fetchBodyChain(srv, sshPath)
	if err != nil {
		t.Fatalf("fetch ssh key: %v", err)
	}
	if sshStatus != 200 {
		t.Fatalf("expected 200 for %q, got %d — check testbed/fakeroot/home/app/.ssh/id_rsa", sshPath, sshStatus)
	}
	if !strings.Contains(string(sshBody), "PRIVATE KEY") {
		t.Errorf("expected PRIVATE KEY in SSH fixture; got: %q", string(sshBody))
	}
	t.Logf("chain E2E: passwd → app user → /home/app/.ssh/id_rsa confirmed (depth=%d via=%s)",
		idRsaTarget.Depth, idRsaTarget.FromFinding)
}

// TestChainE2E_MaxDepthRespected verifies the MaxDepth cap holds.
func TestChainE2E_MaxDepthRespected(t *testing.T) {
	q := chain.New(chain.Config{MaxDepth: 1, MaxTargets: 1000})
	q.Enqueue([]extract.Finding{
		{Type: extract.FindingTypeUser, Key: "app", Source: "/etc/passwd", Extra: map[string]string{"home": "/home/app"}, Depth: 0},
	})
	// Depth-1 findings: their targets would be depth-2, which must be blocked.
	q.Enqueue([]extract.Finding{
		{Type: extract.FindingTypeUser, Key: "sub", Source: "/home/app/.bash_history", Extra: map[string]string{"home": "/home/sub"}, Depth: 1},
	})
	for _, tgt := range q.Targets() {
		if tgt.Depth >= 2 {
			t.Errorf("MaxDepth=1 violated: got target at depth=%d path=%q", tgt.Depth, tgt.Path)
		}
	}
}

// TestChainE2E_MaxTargetsRespected verifies the MaxTargets cap holds.
func TestChainE2E_MaxTargetsRespected(t *testing.T) {
	const cap = 5
	q := chain.New(chain.Config{MaxDepth: 10, MaxTargets: cap})
	var findings []extract.Finding
	for i := 0; i < 20; i++ {
		findings = append(findings, extract.Finding{
			Type:  extract.FindingTypeUser,
			Key:   string(rune('a' + i)),
			Extra: map[string]string{"home": "/home/" + string(rune('a'+i))},
			Depth: 0,
		})
	}
	q.Enqueue(findings)
	if got := len(q.Targets()); got > cap {
		t.Errorf("MaxTargets=%d violated: got %d targets", cap, got)
	}
}
