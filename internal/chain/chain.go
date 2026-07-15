// Package chain implements the follow-on target generation engine. It takes
// extracted findings from confirmed-readable files and generates additional
// targets to attempt, enforcing recursion depth and total-target caps.
package chain

import (
	"path"
	"sync"

	"github.com/bugsyhewitt/exhumed/internal/extract"
)

// Config controls the recursion limits for the chain engine.
type Config struct {
	// MaxDepth is the maximum number of follow-on generations (default 3).
	// A finding at depth N generates targets at depth N+1; targets at
	// depth >= MaxDepth are not added to the queue.
	MaxDepth int
	// MaxTargets is the hard cap on total queued targets (default 500).
	MaxTargets int
}

// Target is a follow-on path to attempt, with provenance metadata.
type Target struct {
	// Path is the file path to attempt (same format as db.Entry.Path).
	Path string
	// Depth is the generation: 1 = directly derived from initial scan, 2 = from a depth-1 finding, etc.
	Depth int
	// FromFinding describes what produced this target (e.g. "user:root from /etc/passwd").
	FromFinding string
}

// Queue manages the set of generated follow-on targets.
type Queue struct {
	mu      sync.Mutex
	cfg     Config
	targets []Target
	seen    map[string]struct{} // dedup by path
}

// New creates a Queue with the given Config. Zero values are replaced with
// safe defaults (MaxDepth=3, MaxTargets=500).
func New(cfg Config) *Queue {
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 3
	}
	if cfg.MaxTargets <= 0 {
		cfg.MaxTargets = 500
	}
	return &Queue{
		cfg:  cfg,
		seen: make(map[string]struct{}),
	}
}

// Targets returns a snapshot of all queued targets.
func (q *Queue) Targets() []Target {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]Target, len(q.targets))
	copy(out, q.targets)
	return out
}

// Enqueue generates follow-on targets from the given findings and adds them
// to the queue, subject to depth and total-count caps.
func (q *Queue) Enqueue(findings []extract.Finding) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, f := range findings {
		q.generateTargets(f)
	}
}

// add inserts a target into the queue if it passes dedup and cap checks.
func (q *Queue) add(path, fromFinding string, depth int) {
	if len(q.targets) >= q.cfg.MaxTargets {
		return
	}
	if _, seen := q.seen[path]; seen {
		return
	}
	q.seen[path] = struct{}{}
	q.targets = append(q.targets, Target{
		Path:        path,
		Depth:       depth,
		FromFinding: fromFinding,
	})
}

// webConfigTargets lists high-value config file names to probe relative to a
// discovered web or app root (DOCUMENT_ROOT, PWD, HOME from proc/environ).
var webConfigTargets = []string{
	".env",
	"config.php",
	"wp-config.php",
	".git/config",
	"settings.py",
	"application.properties",
	"config/database.yml",
	".htpasswd",
}

// homeCredentialTargets lists relative paths probed under a discovered home
// directory regardless of how that directory was found (unix-passwd user entry
// or HOME env-var). Callers append additional paths specific to their finding
// type (e.g. FindingTypeUser adds .mysql_history; FindingTypeInfo/HOME adds .env).
var homeCredentialTargets = []string{
	".ssh/id_rsa",
	".ssh/authorized_keys",
	".aws/credentials",
	".bash_history",
}

// generateTargets applies generation rules for one finding.
func (q *Queue) generateTargets(f extract.Finding) {
	nextDepth := f.Depth + 1
	if nextDepth > q.cfg.MaxDepth {
		return
	}

	switch f.Type {
	case extract.FindingTypeUser:
		home, ok := f.Extra["home"]
		if !ok || home == "" {
			return
		}
		provenance := "user:" + f.Key + " from " + f.Source
		for _, rel := range homeCredentialTargets {
			q.add(home+"/"+rel, provenance, nextDepth)
		}
		q.add(home+"/.mysql_history", provenance, nextDepth) // user-specific

	case extract.FindingTypeGitConfig:
		provenance := "git-config from " + f.Source
		// .git/config presence → queue HEAD and index.
		// Resolve the .git dir from the source path.
		gitDir := gitDirFrom(f.Source)
		q.add(gitDir+"/HEAD", provenance, nextDepth)
		q.add(gitDir+"/index", provenance, nextDepth)

	case extract.FindingTypePath:
		// Config files that reveal a path (log path, backup path, etc.).
		if f.Value != "" {
			q.add(f.Value, "path revealed in "+f.Source, nextDepth)
		}

	case extract.FindingTypeInfo:
		// Env-var findings from /proc/self/environ. Path-type keys (DOCUMENT_ROOT,
		// PWD) reveal the web/app root; queue high-value config files relative to it.
		// HOME reveals the process user's home dir; queue credential files.
		if !isAbsPath(f.Value) {
			return
		}
		root := f.Value
		provenance := f.Key + "=" + root + " from " + f.Source
		switch f.Key {
		case "DOCUMENT_ROOT", "PWD":
			for _, rel := range webConfigTargets {
				q.add(root+"/"+rel, provenance, nextDepth)
			}
		case "HOME":
			for _, rel := range homeCredentialTargets {
				q.add(root+"/"+rel, provenance, nextDepth)
			}
			q.add(root+"/.env", provenance, nextDepth) // env-specific
		}
	}
}

// isAbsPath reports whether s is an absolute filesystem path and long enough
// to be a meaningful root (bare "/" is excluded as a chain target).
func isAbsPath(s string) bool {
	return len(s) > 1 && path.IsAbs(s)
}

// gitDirFrom resolves the .git directory from a .git/config source path.
// E.g. "/var/www/html/.git/config" → "/var/www/html/.git"
func gitDirFrom(source string) string {
	if source == "" {
		return ".git"
	}
	dir := path.Dir(source)
	if dir == "." || dir == "/" {
		return ".git"
	}
	return dir
}
