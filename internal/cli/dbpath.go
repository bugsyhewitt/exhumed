package cli

import (
	"fmt"
	"io"

	"github.com/bugsyhewitt/exhumed/internal/feed"
)

// defaultDBPath is the bundled, in-repo database directory used when --db is
// left at its default value. It is the source of truth shipped inside the
// binary's repository; the feed cache (see defaultCacheDir) overrides it once
// a newer database has been installed via `exhumed update`.
const defaultDBPath = "database"

// dbSourceBundled and dbSourceCache label which database the resolver selected.
const (
	dbSourceBundled  = "bundled"
	dbSourceCache    = "cache"
	dbSourceExplicit = "explicit"
)

// ResolveDBPath decides which database directory scan/db commands should load.
//
// An explicit --db value (anything other than the default defaultDBPath) always
// wins and disables the resolver — the operator asked for a specific directory,
// so honour it verbatim.
//
// When --db is left at its default, ResolveDBPath compares the feed cache
// (cacheDir, normally defaultCacheDir()) against the bundled database. If the
// cache has been populated by `exhumed update` and records a database version
// newer than the bundled one, the cache path is returned; otherwise the bundled
// path is returned. The comparison reuses the feed's own version logic and reads
// only local version markers — it performs no network access.
//
// source is one of dbSourceExplicit, dbSourceCache, or dbSourceBundled and is
// suitable for surfacing to the operator in verbose output.
func ResolveDBPath(explicit, cacheDir string) (path, source string) {
	if explicit != defaultDBPath {
		return explicit, dbSourceExplicit
	}

	cacheVersion := feed.LocalVersion(cacheDir)
	if cacheVersion == "" {
		// No feed-managed database has been installed; the cache is empty.
		return defaultDBPath, dbSourceBundled
	}

	bundledVersion := feed.LocalVersion(defaultDBPath)
	if feed.IsNewer(cacheVersion, bundledVersion) {
		return cacheDir, dbSourceCache
	}
	return defaultDBPath, dbSourceBundled
}

// resolvedDBPath applies ResolveDBPath against the default feed cache and,
// when verbose is set, prints the chosen source to w (typically stderr). It is
// the single entry point the scan and db commands use so the verbose line is
// formatted identically everywhere.
func resolvedDBPath(explicit string, verbose bool, w io.Writer) string {
	path, source := ResolveDBPath(explicit, defaultCacheDir())
	if verbose {
		version := feed.LocalVersion(path)
		if version == "" {
			version = "unknown"
		}
		fmt.Fprintf(w, "[*] database: %s (%s, %s)\n", path, source, version)
	}
	return path
}
