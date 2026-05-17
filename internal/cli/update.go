package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/bugsyhewitt/exhumed/internal/db"
	"github.com/bugsyhewitt/exhumed/internal/feed"
	"github.com/spf13/cobra"
)

// defaultFeedURL is the canonical manifest URL for the exhumed database feed.
const defaultFeedURL = "https://raw.githubusercontent.com/bugsyhewitt/exhumed/main/database/feed/manifest.json"

// defaultCacheDir returns the OS-appropriate user data directory for the feed cache.
func defaultCacheDir() string {
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("APPDATA"); d != "" {
			return filepath.Join(d, "exhumed", "db")
		}
	case "darwin":
		if d := os.Getenv("HOME"); d != "" {
			return filepath.Join(d, "Library", "Application Support", "exhumed", "db")
		}
	}
	// Linux / XDG.
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "exhumed", "db")
	}
	if d := os.Getenv("HOME"); d != "" {
		return filepath.Join(d, ".local", "share", "exhumed", "db")
	}
	return filepath.Join(os.TempDir(), "exhumed-db")
}

type updateFlags struct {
	feedURL   string
	cacheDir  string
	checkOnly bool
}

func newUpdateCmd() *cobra.Command {
	var f updateFlags

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update the file database from the remote feed",
		Long: `update fetches the remote database manifest, verifies SHA-256 checksums,
and atomically installs newer database files into the local cache.

  exhumed update                   # apply update if available
  exhumed update --check           # report availability without applying

The cached database is used by scan, db validate, and db stats in addition
to the bundled database/ directory. Use --db <cachedir> to explicitly load
from the cached location.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(f)
		},
	}

	cmd.Flags().StringVar(&f.feedURL, "feed-url", defaultFeedURL, "URL of the remote feed manifest")
	cmd.Flags().StringVar(&f.cacheDir, "cache-dir", defaultCacheDir(), "Local directory for downloaded database files")
	cmd.Flags().BoolVar(&f.checkOnly, "check", false, "Check for updates without downloading")

	return cmd
}

func runUpdate(f updateFlags) error {
	cfg := feed.Config{
		FeedURL:         f.feedURL,
		CacheDir:        f.cacheDir,
		SupportedSchema: db.SchemaVersion,
	}

	if f.checkOnly {
		info, err := feed.Check(cfg)
		if err != nil {
			return fmt.Errorf("check update: %w", err)
		}
		if info.UpdateAvailable {
			fmt.Printf("Update available: %s → %s\n", info.LocalVersion, info.RemoteVersion)
			fmt.Printf("Run 'exhumed update' to apply.\n")
		} else {
			if info.LocalVersion == "" {
				fmt.Println("No cached database installed. Run 'exhumed update' to download.")
			} else {
				fmt.Printf("Database is up to date (%s).\n", info.LocalVersion)
			}
		}
		return nil
	}

	fmt.Printf("Checking feed: %s\n", f.feedURL)
	changed, err := feed.Update(cfg)
	if err != nil {
		return fmt.Errorf("update failed: %w", err)
	}
	if changed {
		fmt.Printf("✓ Database updated. Cache: %s\n", f.cacheDir)
	} else {
		fmt.Println("Database is already up to date.")
	}
	return nil
}
