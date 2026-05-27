package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bugsyhewitt/exhumed/internal/chain"
	"github.com/bugsyhewitt/exhumed/internal/db"
	"github.com/bugsyhewitt/exhumed/internal/detect"
	"github.com/bugsyhewitt/exhumed/internal/engine"
	"github.com/bugsyhewitt/exhumed/internal/extract"
	"github.com/bugsyhewitt/exhumed/internal/inject"
	"github.com/bugsyhewitt/exhumed/internal/output"
	"github.com/bugsyhewitt/exhumed/internal/traversal"
	"github.com/spf13/cobra"
)

// scanFlags holds the parsed flag values for the scan command.
type scanFlags struct {
	url            string
	marker         string
	method         string
	data           string
	headers        []string
	cookies        []string
	concurrency    int
	rate           float64
	timeout        time.Duration
	proxy          string
	insecure       bool
	traversalDepth int
	verbose        bool
	dbPath         string
	onlyHits       bool
	showSecrets    bool
	maxDepth       int
	maxTargets     int
	outputFormat   string
}

func newScanCmd() *cobra.Command {
	var f scanFlags

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a URL for LFI vulnerabilities",
		Long: `scan loads the file database and fires traversal payloads at a target URL
parameter, walking every database entry to find readable files.

The URL must contain the marker string (default FUZZ) at the injection point:

  exhumed scan --url "http://target.local/?file=FUZZ"

Confirmed hits use the confirm block from each database entry. Extracted
findings feed a follow-on chain engine that queues derived targets (SSH keys
from home dirs, etc.) up to --max-depth generations.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(f)
		},
	}

	cmd.Flags().StringVarP(&f.url, "url", "u", "", "Target URL containing the injection marker (required)")
	cmd.Flags().StringVarP(&f.marker, "marker", "m", "FUZZ", "Placeholder string to substitute with payloads")
	cmd.Flags().StringVarP(&f.method, "method", "X", "GET", "HTTP method")
	cmd.Flags().StringVarP(&f.data, "data", "d", "", "Request body for POST/PUT")
	cmd.Flags().StringArrayVarP(&f.headers, "header", "H", nil, "Extra header (repeatable): 'Name: value'")
	cmd.Flags().StringArrayVarP(&f.cookies, "cookie", "b", nil, "Cookie (repeatable): 'name=value'")
	cmd.Flags().IntVarP(&f.concurrency, "concurrency", "c", 10, "Number of concurrent workers")
	cmd.Flags().Float64Var(&f.rate, "rate", 0, "Max requests/sec (0 = unlimited)")
	cmd.Flags().DurationVar(&f.timeout, "timeout", 10*time.Second, "Per-request timeout")
	cmd.Flags().StringVar(&f.proxy, "proxy", "", "HTTP proxy URL (e.g. http://127.0.0.1:8080)")
	cmd.Flags().BoolVar(&f.insecure, "insecure", false, "Skip TLS certificate verification")
	cmd.Flags().IntVar(&f.traversalDepth, "traversal-depth", 8, "Max directory traversal depth")
	cmd.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().BoolVar(&f.onlyHits, "only-hits", false, "Suppress unconfirmed responses from output")
	cmd.Flags().BoolVar(&f.showSecrets, "show-secrets", false, "Print secret values in full (default: partially redacted)")
	cmd.Flags().IntVar(&f.maxDepth, "max-depth", 3, "Max follow-on chain depth (0 = disable chaining)")
	cmd.Flags().IntVar(&f.maxTargets, "max-targets", 500, "Hard cap on total follow-on targets")
	cmd.Flags().StringVar(&f.dbPath, "db", defaultDBPath, "Path to database root (defaults to the freshest of the bundled DB and the feed cache)")
	cmd.Flags().StringVar(&f.outputFormat, "output", "text", "Output format: text or json")

	_ = cmd.MarkFlagRequired("url")

	return cmd
}

// hitRecord stores a single confirmed LFI hit for summary output.
type hitRecord struct {
	entryID   string
	path      string
	technique string
	status    int
	snippets  []string
	findings  []extract.Finding
	elapsed   time.Duration
}

func runScan(f scanFlags) error {
	outFmt, err := output.ParseFormat(f.outputFormat)
	if err != nil {
		return err
	}

	if !strings.Contains(f.url, f.marker) && !strings.Contains(f.data, f.marker) {
		return fmt.Errorf("marker %q not found in --url or --data; add it at the injection point", f.marker)
	}

	// Resolve --db: prefer the freshest available source. When --db is left at
	// its default, an up-to-date feed cache transparently overrides the bundled
	// database so `exhumed update` actually takes effect.
	f.dbPath = resolvedDBPath(f.dbPath, f.verbose && outFmt == output.FormatText, os.Stderr)

	var database *db.Database
	if strings.HasSuffix(strings.TrimRight(f.dbPath, "/\\"), "_raw") {
		database, err = db.LoadDir(f.dbPath)
	} else {
		database, err = db.LoadCurated(f.dbPath)
	}
	if err != nil {
		return fmt.Errorf("load database %q: %w", f.dbPath, err)
	}

	entries := database.AllEntries()
	if len(entries) == 0 {
		fmt.Fprintf(os.Stderr, "info: database at %q is empty\n", f.dbPath)
		return nil
	}

	if f.verbose && outFmt == output.FormatText {
		fmt.Fprintf(os.Stderr, "[*] Loaded %d entries from %q\n", len(entries), f.dbPath)
	}

	tmpl := inject.NewRequest(f.method, f.url)
	for _, h := range f.headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid header format %q: expected 'Name: value'", h)
		}
		tmpl.Headers.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}
	for _, c := range f.cookies {
		parts := strings.SplitN(c, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid cookie format %q: expected 'name=value'", c)
		}
		tmpl.Cookies[parts[0]] = parts[1]
	}
	if f.data != "" {
		tmpl.Body = []byte(f.data)
	}

	surfaces := inject.FindSurfaces(tmpl, f.marker)
	if len(surfaces) == 0 {
		return fmt.Errorf("marker %q not found in any injection surface", f.marker)
	}
	if f.verbose && outFmt == output.FormatText {
		fmt.Fprintf(os.Stderr, "[*] Injection surfaces: %v\n", surfaces)
	}

	eng := engine.New(engine.Config{
		Concurrency: f.concurrency,
		RatePerSec:  f.rate,
		Timeout:     f.timeout,
		ProxyURL:    f.proxy,
		Insecure:    f.insecure,
	})

	ctx := context.Background()
	chainQ := chain.New(chain.Config{MaxDepth: f.maxDepth, MaxTargets: f.maxTargets})

	scanStart := time.Now()
	var jsonWriter *output.JSONWriter
	if outFmt == output.FormatJSON {
		jsonWriter = output.NewJSONWriter(f.url, scanStart)
	}

	var hits []hitRecord
	total, confirmed := 0, 0

	// Phase 1: walk every database entry.
	for _, entry := range entries {
		rec, requests := scanEntry(ctx, eng, tmpl, f, entry)
		total += requests
		if rec != nil {
			confirmed++
			hits = append(hits, *rec)
			if outFmt == output.FormatText {
				printHit(*rec, f.showSecrets)
			} else {
				jsonWriter.AddHit(rec.entryID, rec.path, rec.technique, rec.status,
					rec.elapsed, rec.snippets, rec.findings, f.showSecrets, 0)
			}
			// Feed extraction findings into chain engine.
			chainQ.Enqueue(rec.findings)
		}
	}

	// Phase 2: walk follow-on chain targets.
	chainTargets := chainQ.Targets()
	if len(chainTargets) > 0 && f.maxDepth > 0 {
		if outFmt == output.FormatText {
			fmt.Printf("\n── Follow-on chain (%d targets) ──────────────────────\n", len(chainTargets))
		}
		for _, tgt := range chainTargets {
			// Synthesise a minimal entry for the chain target using the best-effort parser.
			chainEntry := synthEntry(tgt.Path)
			rec, requests := scanEntry(ctx, eng, tmpl, f, chainEntry)
			total += requests
			if rec != nil {
				confirmed++
				hits = append(hits, *rec)
				if outFmt == output.FormatText {
					fmt.Printf("[CHAIN-HIT depth=%d via=%s]\n", tgt.Depth, tgt.FromFinding)
					printHit(*rec, f.showSecrets)
				} else {
					jsonWriter.AddHit(rec.entryID, rec.path, rec.technique, rec.status,
						rec.elapsed, rec.snippets, rec.findings, f.showSecrets, tgt.Depth)
				}
			}
		}
	}

	if outFmt == output.FormatJSON {
		return jsonWriter.Finalise(os.Stdout, total, len(chainTargets))
	}

	// Text summary.
	fmt.Printf("\n── Scan complete ──────────────────────────────────────\n")
	fmt.Printf("Requests: %d  |  Confirmed readable: %d  |  Chain targets: %d\n",
		total, confirmed, len(chainTargets))

	if len(hits) > 0 {
		fmt.Printf("\n── Confirmed hits ─────────────────────────────────────\n")
		for _, h := range hits {
			fmt.Printf("  ✓ %-30s  %s  (via %s)\n", h.entryID, h.path, h.technique)
		}
	}

	return nil
}

// scanEntry fires all traversal payloads for one entry and returns the first
// confirmed hit (if any) plus the total request count.
func scanEntry(ctx context.Context, eng *engine.Engine, tmpl engine.Request, f scanFlags, entry db.CompiledEntry) (*hitRecord, int) {
	payloads := traversal.Generate(entry.Entry.Path, f.traversalDepth)
	reqs := make([]engine.Request, len(payloads))
	for i, p := range payloads {
		reqs[i] = inject.Substitute(tmpl, f.marker, p.Value)
	}

	results := eng.Run(ctx, reqs)
	for i, r := range results {
		if r.Err != nil {
			if f.verbose {
				fmt.Fprintf(os.Stderr, "[!] %s — %v\n", r.URL, r.Err)
			}
			continue
		}
		d := detect.Check(entry, r)
		tech := payloads[i].Technique
		if d.Hit {
			parser := entry.Entry.Parser
			if parser == "" {
				parser = "generic-secrets"
			}
			findings := extract.Parse(parser, r.Body, entry.Entry.Path)
			return &hitRecord{
				entryID:   entry.Entry.ID,
				path:      entry.Entry.Path,
				technique: tech,
				status:    r.StatusCode,
				snippets:  d.Snippets,
				findings:  findings,
				elapsed:   r.Elapsed,
			}, len(results)
		}
		if !f.onlyHits {
			fmt.Printf("[responded] entry=%s technique=%s status=%d bytes=%d confidence=%q\n",
				entry.Entry.ID, tech, r.StatusCode, len(r.Body), d.Confidence)
		}
	}
	return nil, len(results)
}

// synthEntry builds a minimal CompiledEntry for a chain follow-on target.
// Uses a weak-confirm (any non-empty body) so any readable file is a hit.
func synthEntry(path string) db.CompiledEntry {
	parser := "generic-secrets"
	if strings.Contains(path, "id_rsa") || strings.Contains(path, "id_ed25519") {
		parser = "ssh-key"
	} else if strings.Contains(path, "passwd") {
		parser = "unix-passwd"
	} else if strings.Contains(path, ".env") || strings.Contains(path, ".cfg") || strings.Contains(path, ".conf") {
		parser = "ini-config"
	}
	return db.CompiledEntry{
		Entry: db.Entry{
			ID:        "chain:" + path,
			Name:      path,
			Path:      path,
			OS:        []string{"linux"},
			InfoGoal:  db.InfoGoalCredentials,
			Privilege: db.PrivilegeAppUser,
			Parser:    parser,
			Confirm: db.Confirm{
				Type:     db.ConfirmTypeRegex,
				Patterns: []string{`.`},
			},
		},
	}
}

func printHit(h hitRecord, showSecrets bool) {
	fmt.Printf("[CONFIRMED] entry=%s path=%s technique=%s status=%d elapsed=%s\n",
		h.entryID, h.path, h.technique, h.status, h.elapsed.Round(time.Millisecond))
	for _, snip := range h.snippets {
		fmt.Printf("    snippet: %s\n", snip)
	}
	for _, f := range h.findings {
		fmt.Printf("    [finding] %s: %s = %s (confidence=%.0f%%)\n",
			f.Type, f.Key, f.DisplayValue(showSecrets), f.Confidence*100)
	}
}
