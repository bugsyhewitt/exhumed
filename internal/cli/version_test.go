package cli

import (
	"bytes"
	"strings"
	"testing"
)

// TestVersionCmd_Plain verifies the bare `version` command prints the binary
// version line and does NOT print a database line.
func TestVersionCmd_Plain(t *testing.T) {
	cmd := newVersionCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := out.String()
	if !strings.HasPrefix(got, "exhumed ") {
		t.Errorf("expected output to start with %q, got %q", "exhumed ", got)
	}
	if strings.Contains(got, "database ") {
		t.Errorf("plain version must not print a database line, got %q", got)
	}
}

// TestVersionCmd_DBFlag verifies `version --db` surfaces the active database
// version and source. With no feed cache installed, it must report the bundled
// source and the bundled version marker (or "unknown" when absent).
func TestVersionCmd_DBFlag(t *testing.T) {
	withBundledDB(t, "2026-05-17")

	cmd := newVersionCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--db"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "database 2026-05-17") {
		t.Errorf("expected resolved database version in output, got %q", got)
	}
	if !strings.Contains(got, dbSourceBundled) {
		t.Errorf("expected source %q in output, got %q", dbSourceBundled, got)
	}
}

// TestVersionCmd_DBFlag_UnknownVersion verifies the command degrades gracefully
// to "unknown" when the resolved database has no version marker.
func TestVersionCmd_DBFlag_UnknownVersion(t *testing.T) {
	withBundledDB(t, "") // bundled dir exists but carries no version marker

	cmd := newVersionCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--db"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out.String(), "database unknown") {
		t.Errorf("expected %q in output, got %q", "database unknown", out.String())
	}
}
