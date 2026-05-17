// Package db implements the exhumed file-path database: schema structs,
// YAML loader, and structural validator. The database is the moat of the tool —
// it encodes which files matter, why, and how to confirm a successful read.
package db

import "regexp"

// SchemaVersion is the only database schema version this loader understands.
// Files declaring a different version are rejected at load time.
const SchemaVersion = 1

// ── Controlled vocabularies ───────────────────────────────────────────────────

// Category classifies a group of database entries by the technology domain.
type Category string

const (
	CategoryOS              Category = "os"
	CategoryWebserver       Category = "webserver"
	CategoryApplication     Category = "application"
	CategoryFramework       Category = "framework"
	CategoryDatabase        Category = "database"
	CategoryLanguageRuntime Category = "language-runtime"
	CategoryContainer       Category = "container"
	CategoryCloud           Category = "cloud"
	CategoryCICD            Category = "ci-cd"
	CategoryVersionControl  Category = "version-control"
	CategoryCredentialStore Category = "credential-store"
	CategoryMisc            Category = "misc"
)

// ValidCategories is the exhaustive set accepted by the validator.
var ValidCategories = map[Category]struct{}{
	CategoryOS: {}, CategoryWebserver: {}, CategoryApplication: {},
	CategoryFramework: {}, CategoryDatabase: {}, CategoryLanguageRuntime: {},
	CategoryContainer: {}, CategoryCloud: {}, CategoryCICD: {},
	CategoryVersionControl: {}, CategoryCredentialStore: {}, CategoryMisc: {},
}

// InfoGoal describes what an attacker gains by reading the file.
type InfoGoal string

const (
	InfoGoalCredentials    InfoGoal = "credentials"
	InfoGoalConfig         InfoGoal = "config"
	InfoGoalSourceCode     InfoGoal = "source-code"
	InfoGoalSessionData    InfoGoal = "session-data"
	InfoGoalLogs           InfoGoal = "logs"
	InfoGoalSSHKeys        InfoGoal = "ssh-keys"
	InfoGoalTLSKeys        InfoGoal = "tls-keys"
	InfoGoalTokens         InfoGoal = "tokens"
	InfoGoalCron           InfoGoal = "cron"
	InfoGoalCommandHistory InfoGoal = "command-history"
	InfoGoalSystemInfo     InfoGoal = "system-info"
	InfoGoalNetworkInfo    InfoGoal = "network-info"
	InfoGoalDatabaseData   InfoGoal = "database-data"
	InfoGoalEnvironment    InfoGoal = "environment"
	InfoGoalServiceAccount InfoGoal = "service-account"
)

// ValidInfoGoals is the exhaustive set accepted by the validator.
var ValidInfoGoals = map[InfoGoal]struct{}{
	InfoGoalCredentials: {}, InfoGoalConfig: {}, InfoGoalSourceCode: {},
	InfoGoalSessionData: {}, InfoGoalLogs: {}, InfoGoalSSHKeys: {},
	InfoGoalTLSKeys: {}, InfoGoalTokens: {}, InfoGoalCron: {},
	InfoGoalCommandHistory: {}, InfoGoalSystemInfo: {}, InfoGoalNetworkInfo: {},
	InfoGoalDatabaseData: {}, InfoGoalEnvironment: {}, InfoGoalServiceAccount: {},
}

// Privilege describes the read permission typically required.
type Privilege string

const (
	PrivilegeAny      Privilege = "any"      // world-readable
	PrivilegeAppUser  Privilege = "app-user" // readable by the web app process
	PrivilegeElevated Privilege = "elevated" // root/admin typically required
	PrivilegeUnknown  Privilege = "unknown"
)

// ValidPrivileges is the exhaustive set accepted by the validator.
var ValidPrivileges = map[Privilege]struct{}{
	PrivilegeAny: {}, PrivilegeAppUser: {}, PrivilegeElevated: {}, PrivilegeUnknown: {},
}

// ValidOSValues is the set of accepted OS family strings.
var ValidOSValues = map[string]struct{}{
	"linux": {}, "windows": {}, "bsd": {}, "macos": {},
}

// ConfirmType determines how patterns in a Confirm block are matched.
type ConfirmType string

const (
	ConfirmTypeRegex      ConfirmType = "regex"
	ConfirmTypeKeyword    ConfirmType = "keyword"
	ConfirmTypeKeywordAll ConfirmType = "keyword-all"
)

// ValidConfirmTypes is the exhaustive set accepted by the validator.
var ValidConfirmTypes = map[ConfirmType]struct{}{
	ConfirmTypeRegex: {}, ConfirmTypeKeyword: {}, ConfirmTypeKeywordAll: {},
}

// ── YAML structs ──────────────────────────────────────────────────────────────

// GroupFile is the top-level structure of each YAML database file.
// schema_version must equal SchemaVersion; unknown versions are rejected.
type GroupFile struct {
	SchemaVersion int     `yaml:"schema_version"`
	Group         Group   `yaml:"group"`
	Entries       []Entry `yaml:"entries"`
}

// Group holds metadata shared by all entries in one YAML file.
type Group struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	OS          []string `yaml:"os"`
	Category    Category `yaml:"category"`
}

// Entry describes one logical target file.
type Entry struct {
	ID           string    `yaml:"id"`
	Name         string    `yaml:"name"`
	Description  string    `yaml:"description"`
	Path         string    `yaml:"path"`
	AltPaths     []string  `yaml:"alt_paths,omitempty"`
	OS           []string  `yaml:"os"`
	InfoGoal     InfoGoal  `yaml:"info_goal"`
	Privilege    Privilege `yaml:"privilege"`
	Confirm      Confirm   `yaml:"confirm"`
	Parser       string    `yaml:"parser,omitempty"`
	References   []string  `yaml:"references,omitempty"`
	Tags         []string  `yaml:"tags,omitempty"`
	MinTraversal *int      `yaml:"min_traversal,omitempty"`
}

// Confirm specifies how to verify that the file was actually included in the
// response (not just a 200 with an error page).
//
// type: regex — patterns are RE2 regexes; at least min_matches must hit.
// type: keyword — patterns are literal case-insensitive substrings; at least one hits.
// type: keyword-all — ALL patterns must be present.
// negate — if any negate pattern matches, this is NOT a hit even if patterns matched.
type Confirm struct {
	Type       ConfirmType `yaml:"type"`
	Patterns   []string    `yaml:"patterns"`
	MinMatches int         `yaml:"min_matches,omitempty"` // default 1
	Negate     []string    `yaml:"negate,omitempty"`
}

// EffectiveMinMatches returns the number of patterns that must match,
// treating the zero value as 1.
func (c Confirm) EffectiveMinMatches() int {
	if c.MinMatches < 1 {
		return 1
	}
	return c.MinMatches
}

// ── In-memory runtime structs ─────────────────────────────────────────────────

// CompiledEntry is an Entry with its confirm regexes pre-compiled so Packet 03
// never pays the compilation cost per request.
type CompiledEntry struct {
	Entry
	// CompiledPatterns holds the compiled regex for each Confirm.Pattern when
	// Confirm.Type is ConfirmTypeRegex. Indexed to match Confirm.Patterns.
	// Nil for keyword types.
	CompiledPatterns []*regexp.Regexp
	// CompiledNegate holds the compiled regex for each Confirm.Negate entry
	// when Confirm.Type is ConfirmTypeRegex.
	CompiledNegate []*regexp.Regexp
	// SourceFile is the YAML file this entry was loaded from.
	SourceFile string
	// GroupID is the group this entry belongs to.
	GroupID string
}

// Database is the fully-loaded, query-ready in-memory representation of all
// YAML files under a database root. It is safe for concurrent reads after
// construction; no writes occur after Load returns.
type Database struct {
	entries []CompiledEntry
	// groups holds the GroupFile metadata keyed by group id.
	groups map[string]Group
	// byGroup maps group id → slice of entry indices into entries.
	byGroup map[string][]int
	// byOS maps os string → slice of entry indices.
	byOS map[string][]int
	// byCategory maps category string → slice of entry indices.
	byCategory map[string][]int
	// byInfoGoal maps info_goal string → slice of entry indices.
	byInfoGoal map[string][]int
}

// AllEntries returns every loaded entry.
func (d *Database) AllEntries() []CompiledEntry {
	return d.entries
}

// ByGroup returns all entries belonging to the given group id.
func (d *Database) ByGroup(groupID string) []CompiledEntry {
	return d.pick(d.byGroup[groupID])
}

// ByOS returns all entries whose os list includes the given OS family.
func (d *Database) ByOS(os string) []CompiledEntry {
	return d.pick(d.byOS[os])
}

// ByCategory returns all entries belonging to the given category.
func (d *Database) ByCategory(cat string) []CompiledEntry {
	return d.pick(d.byCategory[cat])
}

// ByInfoGoal returns all entries with the given info_goal.
func (d *Database) ByInfoGoal(goal string) []CompiledEntry {
	return d.pick(d.byInfoGoal[goal])
}

// Stats returns aggregate counts for the database.
func (d *Database) Stats() DatabaseStats {
	s := DatabaseStats{
		Total:       len(d.entries),
		PerGroup:    make(map[string]int, len(d.byGroup)),
		PerCategory: make(map[string]int, len(d.byCategory)),
		PerOS:       make(map[string]int, len(d.byOS)),
		PerInfoGoal: make(map[string]int, len(d.byInfoGoal)),
	}
	for k, v := range d.byGroup {
		s.PerGroup[k] = len(v)
	}
	for k, v := range d.byCategory {
		s.PerCategory[k] = len(v)
	}
	for k, v := range d.byOS {
		s.PerOS[k] = len(v)
	}
	for k, v := range d.byInfoGoal {
		s.PerInfoGoal[k] = len(v)
	}
	return s
}

// DatabaseStats is the aggregate stats snapshot returned by Database.Stats().
type DatabaseStats struct {
	Total       int
	PerGroup    map[string]int
	PerCategory map[string]int
	PerOS       map[string]int
	PerInfoGoal map[string]int
}

func (d *Database) pick(indices []int) []CompiledEntry {
	if len(indices) == 0 {
		return nil
	}
	out := make([]CompiledEntry, len(indices))
	for i, idx := range indices {
		out[i] = d.entries[idx]
	}
	return out
}

// newDatabase allocates an empty Database ready for population by the loader.
func newDatabase() *Database {
	return &Database{
		groups:     make(map[string]Group),
		byGroup:    make(map[string][]int),
		byOS:       make(map[string][]int),
		byCategory: make(map[string][]int),
		byInfoGoal: make(map[string][]int),
	}
}
