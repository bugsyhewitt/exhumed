package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bugsyhewitt/exhumed/internal/bodyfilter"
	"github.com/bugsyhewitt/exhumed/internal/chain"
	"github.com/bugsyhewitt/exhumed/internal/codefilter"
	"github.com/bugsyhewitt/exhumed/internal/db"
	"github.com/bugsyhewitt/exhumed/internal/detect"
	"github.com/bugsyhewitt/exhumed/internal/engine"
	"github.com/bugsyhewitt/exhumed/internal/extract"
	"github.com/bugsyhewitt/exhumed/internal/inject"
	"github.com/bugsyhewitt/exhumed/internal/output"
	"github.com/bugsyhewitt/exhumed/internal/pathlist"
	"github.com/bugsyhewitt/exhumed/internal/respfilter"
	"github.com/bugsyhewitt/exhumed/internal/scanstate"
	"github.com/bugsyhewitt/exhumed/internal/timefilter"
	"github.com/bugsyhewitt/exhumed/internal/traversal"
	"github.com/spf13/cobra"
)

// scanFlags holds the parsed flag values for the scan command.
type scanFlags struct {
	url             string
	marker          string
	method          string
	data            string
	headers         []string
	cookies         []string
	concurrency     int
	rate            float64
	timeout         time.Duration
	proxy           string
	insecure        bool
	followRedirects bool
	traversalDepth  int
	techniques      []string
	verbose         bool
	dbPath          string
	onlyHits        bool
	showSecrets     bool
	maxDepth        int
	maxTargets      int
	outputFormat    string
	resume          string
	pathsFile       string
	extensions      []string
	filterSize      string
	filterCode      string
	filterRegex     string
	filterTime      string

	// sizeFilter is the compiled form of filterSize, populated by runScan.
	// It suppresses unconfirmed "[responded]" lines whose body length matches
	// a known-noise size, mirroring the ffuf/gobuster -fs workflow. It never
	// affects confirmed hits.
	sizeFilter *respfilter.Filter

	// codeFilter is the compiled form of filterCode, populated by runScan.
	// It suppresses unconfirmed "[responded]" lines whose status code matches
	// a known-noise code, mirroring the ffuf -fc workflow. It composes with
	// sizeFilter (a response is dropped if either matches) and never affects
	// confirmed hits.
	codeFilter *codefilter.Filter

	// bodyFilter is the compiled form of filterRegex, populated by runScan.
	// It suppresses unconfirmed "[responded]" lines whose response body matches
	// a known-noise regex, mirroring the ffuf -fr workflow. It composes with
	// sizeFilter and codeFilter (a response is dropped if any of the three
	// matches) and never affects confirmed hits.
	bodyFilter *bodyfilter.Filter

	// timeFilter is the compiled form of filterTime, populated by runScan.
	// It suppresses unconfirmed "[responded]" lines whose round-trip duration
	// satisfies a comparator bound (e.g. ">500ms" for slow noise, "<5ms" for
	// instant cache/WAF noise), mirroring the ffuf -ft workflow. It composes
	// with sizeFilter, codeFilter, and bodyFilter (a response is dropped if any
	// of the four matches) and never affects confirmed hits.
	timeFilter *timefilter.Filter
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
	cmd.Flags().BoolVar(&f.followRedirects, "follow-redirects", false, "Follow 3xx redirects (default: report the redirect verbatim without following)")
	cmd.Flags().IntVar(&f.traversalDepth, "traversal-depth", 8, "Max directory traversal depth")
	cmd.Flags().StringSliceVar(&f.techniques, "techniques", nil, "Comma-separated traversal techniques to use (default: all). Use 'list' to print available names.")
	cmd.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().BoolVar(&f.onlyHits, "only-hits", false, "Suppress unconfirmed responses from output")
	cmd.Flags().BoolVar(&f.showSecrets, "show-secrets", false, "Print secret values in full (default: partially redacted)")
	cmd.Flags().IntVar(&f.maxDepth, "max-depth", 3, "Max follow-on chain depth (0 = disable chaining)")
	cmd.Flags().IntVar(&f.maxTargets, "max-targets", 500, "Hard cap on total follow-on targets")
	cmd.Flags().StringVar(&f.dbPath, "db", defaultDBPath, "Path to database root (defaults to the freshest of the bundled DB and the feed cache)")
	cmd.Flags().StringVar(&f.outputFormat, "output", "text", "Output format: text or json")
	cmd.Flags().StringVar(&f.resume, "resume", "", "Persist per-entry progress to this file and skip already-attempted entries on restart")
	cmd.Flags().StringVar(&f.pathsFile, "paths-file", "", "Scan additional file paths from a SecLists-style wordlist (one path per line; '#' comments and blanks ignored)")
	cmd.Flags().StringSliceVar(&f.extensions, "extensions", nil, "Append file extensions to each --paths-file entry (ffuf -e workflow), e.g. '.php,.bak,.old'. A leading dot is optional. Requires --paths-file.")
	cmd.Flags().StringVar(&f.filterSize, "filter-size", "", "Suppress unconfirmed responses whose body length matches a noise size. Comma-separated exact sizes and/or ranges, e.g. '0,413,100-200'. Confirmed hits are never filtered.")
	cmd.Flags().StringVar(&f.filterCode, "filter-code", "", "Suppress unconfirmed responses whose HTTP status matches a noise code. Comma-separated exact codes and/or ranges (100-599), e.g. '404,403,400-499'. Composes with --filter-size; confirmed hits are never filtered.")
	cmd.Flags().StringVar(&f.filterRegex, "filter-regex", "", "Suppress unconfirmed responses whose body matches this regex (RE2, unanchored 'contains' match), e.g. 'Not Found' or '(?i)access denied'. Composes with --filter-size and --filter-code; confirmed hits are never filtered.")
	cmd.Flags().StringVar(&f.filterTime, "filter-time", "", "Suppress unconfirmed responses whose round-trip time matches a comparator bound. Comma-separated terms of '>'/'>='/'<'/'<=' plus a Go duration, e.g. '>500ms' or '>2s,<5ms'. Composes with the other --filter-* flags; confirmed hits are never filtered.")

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

	// Compile the response-noise filters up front so a malformed spec fails
	// before any requests fire.
	f.sizeFilter, err = respfilter.Parse(f.filterSize)
	if err != nil {
		return err
	}
	f.codeFilter, err = codefilter.Parse(f.filterCode)
	if err != nil {
		return err
	}
	f.bodyFilter, err = bodyfilter.Parse(f.filterRegex)
	if err != nil {
		return err
	}
	f.timeFilter, err = timefilter.Parse(f.filterTime)
	if err != nil {
		return err
	}

	if !strings.Contains(f.url, f.marker) && !strings.Contains(f.data, f.marker) {
		return fmt.Errorf("marker %q not found in --url or --data; add it at the injection point", f.marker)
	}

	// Validate --techniques against the generator's known set. Passing the single
	// value "list" prints the available technique names and exits cleanly.
	if len(f.techniques) == 1 && f.techniques[0] == "list" {
		fmt.Println("Available traversal techniques (use with --techniques):")
		for _, t := range traversal.Techniques() {
			fmt.Printf("  %s\n", t)
		}
		return nil
	}
	if len(f.techniques) > 0 {
		valid := make(map[string]bool, len(traversal.Techniques()))
		for _, t := range traversal.Techniques() {
			valid[t] = true
		}
		for _, t := range f.techniques {
			if !valid[t] {
				return fmt.Errorf("unknown technique %q; run with --techniques list to see valid names", t)
			}
		}
	}

	// --extensions only makes sense for wordlist paths (a bare filename like
	// "config" plus ".php"); appending extensions to the curated database's
	// absolute paths (e.g. "/etc/passwd.php") is nonsense. Require --paths-file
	// and validate the spec up front so a malformed extension fails before any
	// request fires.
	if len(f.extensions) > 0 {
		if f.pathsFile == "" {
			return fmt.Errorf("--extensions requires --paths-file (extensions are appended to wordlist entries)")
		}
		if _, err := pathlist.NormalizeExtensions(f.extensions); err != nil {
			return err
		}
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

	if f.verbose && outFmt == output.FormatText {
		fmt.Fprintf(os.Stderr, "[*] Loaded %d entries from %q\n", len(entries), f.dbPath)
	}

	// Append paths from an external SecLists-style wordlist, if provided. Each
	// line becomes a synthetic weak-confirm entry scanned with the normal
	// traversal engine. This is purely additive: the curated database always
	// runs first, the wordlist extends its coverage.
	if f.pathsFile != "" {
		wordlistEntries, err := pathlist.ParseFileWithExtensions(f.pathsFile, f.extensions)
		if err != nil {
			return err
		}
		if f.verbose && outFmt == output.FormatText {
			if len(f.extensions) > 0 {
				fmt.Fprintf(os.Stderr, "[*] Loaded %d paths from wordlist %q (with %d appended extension(s))\n",
					len(wordlistEntries), f.pathsFile, len(f.extensions))
			} else {
				fmt.Fprintf(os.Stderr, "[*] Loaded %d paths from wordlist %q\n", len(wordlistEntries), f.pathsFile)
			}
		}
		entries = append(entries, wordlistEntries...)
	}

	if len(entries) == 0 {
		fmt.Fprintf(os.Stderr, "info: no entries to scan (database at %q is empty and no --paths-file provided)\n", f.dbPath)
		return nil
	}

	// Resumable-scan state. When --resume is set, load (or create) the state
	// file bound to this target/marker/database and skip already-attempted
	// entries. Mismatched bindings fail closed inside scanstate.Load.
	var state *scanstate.State
	if f.resume != "" {
		ids := make([]string, len(entries))
		for i, e := range entries {
			ids[i] = e.Entry.ID
		}
		fp := scanstate.Fingerprint(ids)
		state, err = scanstate.Load(f.resume, f.url, f.marker, fp)
		if err != nil {
			return fmt.Errorf("resume: %w", err)
		}
		if f.verbose && outFmt == output.FormatText && state.AttemptedCount() > 0 {
			fmt.Fprintf(os.Stderr, "[*] Resuming: %d entries already attempted, %d prior hits will be replayed\n",
				state.AttemptedCount(), len(state.Hits()))
		}
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
		Concurrency:     f.concurrency,
		RatePerSec:      f.rate,
		Timeout:         f.timeout,
		ProxyURL:        f.proxy,
		Insecure:        f.insecure,
		FollowRedirects: f.followRedirects,
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

	// Replay confirmed hits from prior resumed runs so the summary reflects them.
	if state != nil {
		for _, h := range state.Hits() {
			confirmed++
			if outFmt == output.FormatText {
				fmt.Printf("[RESUMED-HIT] entry=%s path=%s technique=%s status=%d\n",
					h.EntryID, h.Path, h.Technique, h.Status)
			}
		}
	}

	// Phase 1: walk every database entry.
	for _, entry := range entries {
		// Skip entries already attempted in a prior run.
		if state != nil && state.Attempted(entry.Entry.ID) {
			if f.verbose && outFmt == output.FormatText {
				fmt.Fprintf(os.Stderr, "[*] skip (resumed) entry=%s\n", entry.Entry.ID)
			}
			continue
		}

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

		// Persist progress: mark this entry attempted and flush atomically.
		if state != nil {
			var sh *scanstate.Hit
			if rec != nil {
				sh = &scanstate.Hit{
					EntryID:   rec.entryID,
					Path:      rec.path,
					Technique: rec.technique,
					Status:    rec.status,
				}
			}
			if err := state.Record(entry.Entry.ID, sh); err != nil {
				return fmt.Errorf("resume: persist progress: %w", err)
			}
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
	payloads := traversal.GenerateFiltered(entry.Entry.Path, f.traversalDepth, f.techniques)
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
		// Unconfirmed response: emit unless --only-hits silences everything,
		// --filter-size flags this body length as known noise, --filter-code
		// flags this status code as known noise, --filter-regex matches this
		// body's content as known noise, or --filter-time flags this round-trip
		// duration as known noise. Confirmed hits (handled above) are never
		// affected by any of these gates.
		if !f.onlyHits && !f.sizeFilter.Match(len(r.Body)) && !f.codeFilter.Match(r.StatusCode) && !f.bodyFilter.Match(r.Body) && !f.timeFilter.Match(r.Elapsed) {
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
