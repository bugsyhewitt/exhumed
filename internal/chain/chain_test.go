package chain_test

import (
	"strings"
	"testing"

	"github.com/bugsyhewitt/exhumed/internal/chain"
	"github.com/bugsyhewitt/exhumed/internal/extract"
)

func TestChain_PasswdGeneratesSSHTargets(t *testing.T) {
	q := chain.New(chain.Config{MaxDepth: 3, MaxTargets: 100})
	findings := []extract.Finding{
		{
			Type:   extract.FindingTypeUser,
			Key:    "app",
			Source: "/etc/passwd",
			Extra:  map[string]string{"home": "/home/app"},
			Depth:  0,
		},
	}
	q.Enqueue(findings)
	targets := q.Targets()
	var hasIDRsa bool
	for _, tgt := range targets {
		if tgt.Path == "/home/app/.ssh/id_rsa" {
			hasIDRsa = true
		}
	}
	if !hasIDRsa {
		t.Errorf("expected /home/app/.ssh/id_rsa in targets; got: %v", targetPaths(targets))
	}
}

func TestChain_PasswdGeneratesAllHomeTargets(t *testing.T) {
	q := chain.New(chain.Config{MaxDepth: 3, MaxTargets: 100})
	q.Enqueue([]extract.Finding{
		{Type: extract.FindingTypeUser, Key: "root", Source: "/etc/passwd", Extra: map[string]string{"home": "/root"}, Depth: 0},
	})
	paths := targetPaths(q.Targets())
	expected := []string{
		"/root/.ssh/id_rsa",
		"/root/.ssh/authorized_keys",
		"/root/.bash_history",
		"/root/.aws/credentials",
	}
	for _, want := range expected {
		if !contains(paths, want) {
			t.Errorf("expected %q in targets; got: %v", want, paths)
		}
	}
}

func TestChain_Deduplication(t *testing.T) {
	q := chain.New(chain.Config{MaxDepth: 3, MaxTargets: 100})
	// Same user twice → same home-dir targets generated twice → should deduplicate.
	findings := []extract.Finding{
		{Type: extract.FindingTypeUser, Key: "app", Source: "/etc/passwd", Extra: map[string]string{"home": "/home/app"}, Depth: 0},
		{Type: extract.FindingTypeUser, Key: "app", Source: "/etc/passwd", Extra: map[string]string{"home": "/home/app"}, Depth: 0},
	}
	q.Enqueue(findings)
	targets := q.Targets()
	var count int
	for _, tgt := range targets {
		if tgt.Path == "/home/app/.ssh/id_rsa" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 /home/app/.ssh/id_rsa, got %d", count)
	}
}

func TestChain_MaxDepthEnforced(t *testing.T) {
	q := chain.New(chain.Config{MaxDepth: 1, MaxTargets: 1000})
	// Depth 0 finding generates depth-1 targets; those are fine.
	q.Enqueue([]extract.Finding{
		{Type: extract.FindingTypeUser, Key: "app", Source: "/etc/passwd", Extra: map[string]string{"home": "/home/app"}, Depth: 0},
	})
	// Simulate depth-1 findings arriving; depth-2 targets must NOT be queued.
	q.Enqueue([]extract.Finding{
		{Type: extract.FindingTypeUser, Key: "app2", Source: "/home/app/.bash_history", Extra: map[string]string{"home": "/home/app2"}, Depth: 1},
	})
	targets := q.Targets()
	for _, tgt := range targets {
		if tgt.Depth >= 2 {
			t.Errorf("expected no targets at depth >= 2 with MaxDepth=1, got path=%q depth=%d", tgt.Path, tgt.Depth)
		}
	}
}

func TestChain_MaxTargetsEnforced(t *testing.T) {
	q := chain.New(chain.Config{MaxDepth: 10, MaxTargets: 3})
	var findings []extract.Finding
	for i := 0; i < 10; i++ {
		findings = append(findings, extract.Finding{
			Type:  extract.FindingTypeUser,
			Key:   string(rune('a' + i)),
			Extra: map[string]string{"home": "/home/" + string(rune('a'+i))},
			Depth: 0,
		})
	}
	q.Enqueue(findings)
	targets := q.Targets()
	if len(targets) > 3 {
		t.Errorf("expected <= 3 targets with MaxTargets=3, got %d", len(targets))
	}
}

func TestChain_ProvenanceRecorded(t *testing.T) {
	q := chain.New(chain.Config{MaxDepth: 3, MaxTargets: 100})
	q.Enqueue([]extract.Finding{
		{Type: extract.FindingTypeUser, Key: "app", Source: "/etc/passwd", Extra: map[string]string{"home": "/home/app"}, Depth: 0},
	})
	for _, tgt := range q.Targets() {
		if tgt.Path == "/home/app/.ssh/id_rsa" {
			if tgt.FromFinding == "" {
				t.Error("expected provenance (FromFinding) to be set")
			}
			if tgt.Depth != 1 {
				t.Errorf("expected depth=1, got %d", tgt.Depth)
			}
			return
		}
	}
	t.Error("/home/app/.ssh/id_rsa not found in targets")
}

func TestChain_GitConfigGeneratesFollowons(t *testing.T) {
	q := chain.New(chain.Config{MaxDepth: 3, MaxTargets: 100})
	q.Enqueue([]extract.Finding{
		{Type: extract.FindingTypeGitConfig, Key: ".git/config", Source: "/var/www/html/.git/config", Depth: 0},
	})
	paths := targetPaths(q.Targets())
	for _, want := range []string{".git/HEAD", ".git/index"} {
		if !containsSubstring(paths, want) {
			t.Errorf("expected path containing %q in targets; got: %v", want, paths)
		}
	}
}

// helpers

func targetPaths(targets []chain.Target) []string {
	paths := make([]string, len(targets))
	for i, tgt := range targets {
		paths[i] = tgt.Path
	}
	return paths
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func containsSubstring(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
