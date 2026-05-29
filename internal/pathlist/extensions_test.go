package pathlist

import (
	"strings"
	"testing"
)

func TestNormalizeExtensions(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"empty slice", []string{}, nil},
		{"adds leading dot", []string{"php"}, []string{".php"}},
		{"keeps existing dot", []string{".bak"}, []string{".bak"}},
		{"trims whitespace", []string{"  .old  "}, []string{".old"}},
		{"preserves case", []string{"PHP"}, []string{".PHP"}},
		{"mixed forms", []string{"php", ".bak", "old"}, []string{".php", ".bak", ".old"}},
		{"skips empty terms", []string{"php", "", "  "}, []string{".php"}},
		{"dedup first-wins", []string{"php", ".php", "php"}, []string{".php"}},
		{"dedup across forms", []string{".bak", "bak"}, []string{".bak"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeExtensions(tc.in)
			if err != nil {
				t.Fatalf("NormalizeExtensions(%v): unexpected error %v", tc.in, err)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("NormalizeExtensions(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeExtensions_Rejects(t *testing.T) {
	cases := []struct {
		name string
		in   []string
	}{
		{"contains slash", []string{"php/x"}},
		{"contains backslash", []string{`php\x`}},
		{"contains internal space", []string{".tar gz"}},
		{"bare dot", []string{"."}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NormalizeExtensions(tc.in)
			if err == nil {
				t.Fatalf("NormalizeExtensions(%v): expected error, got nil", tc.in)
			}
			if !strings.Contains(err.Error(), "pathlist") {
				t.Errorf("error %q should mention pathlist", err)
			}
		})
	}
}

func TestParseWithExtensions_AppendsVariants(t *testing.T) {
	in := "config\nadmin\n"
	entries, err := ParseWithExtensions(strings.NewReader(in), "test", []string{"php", ".bak"})
	if err != nil {
		t.Fatalf("ParseWithExtensions: %v", err)
	}

	// For each base path: bare, then each extension variant in order.
	want := []string{
		"config", "config.php", "config.bak",
		"admin", "admin.php", "admin.bak",
	}
	got := make([]string, len(entries))
	for i, e := range entries {
		got[i] = e.Entry.Path
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("paths = %v, want %v", got, want)
	}
}

// TestParseWithExtensions_DedupesAgainstBase ensures a base path that already
// ends in a requested extension is not scanned twice.
func TestParseWithExtensions_DedupesAgainstBase(t *testing.T) {
	in := "config.php\nconfig\n"
	entries, err := ParseWithExtensions(strings.NewReader(in), "test", []string{"php"})
	if err != nil {
		t.Fatalf("ParseWithExtensions: %v", err)
	}
	got := make([]string, len(entries))
	for i, e := range entries {
		got[i] = e.Entry.Path
	}
	// Line 1 "config.php": bare emitted, then its ".php" variant "config.php.php".
	// Line 2 "config": bare emitted, then its ".php" variant "config.php" — which
	// collides with the line-1 base and is dropped.
	want := []string{"config.php", "config.php.php", "config"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("paths = %v, want %v", got, want)
	}
}

func TestParseWithExtensions_NoExtensionsMatchesParse(t *testing.T) {
	in := "/etc/passwd\n/var/www/.env\n"
	withExt, err := ParseWithExtensions(strings.NewReader(in), "test", nil)
	if err != nil {
		t.Fatalf("ParseWithExtensions: %v", err)
	}
	plain, err := Parse(strings.NewReader(in), "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(withExt) != len(plain) {
		t.Fatalf("nil extensions changed entry count: %d vs %d", len(withExt), len(plain))
	}
}

// TestParseWithExtensions_VariantInfersParser checks that an appended-extension
// variant runs the right format-aware parser (e.g. config.env -> ini-config).
func TestParseWithExtensions_VariantInfersParser(t *testing.T) {
	entries, err := ParseWithExtensions(strings.NewReader("config\n"), "test", []string{".env"})
	if err != nil {
		t.Fatalf("ParseWithExtensions: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if got := entries[1].Entry.Path; got != "config.env" {
		t.Fatalf("variant path = %q, want config.env", got)
	}
	if got := entries[1].Entry.Parser; got != "ini-config" {
		t.Errorf("variant parser = %q, want ini-config", got)
	}
}

func TestParseWithExtensions_RejectsBadExtension(t *testing.T) {
	_, err := ParseWithExtensions(strings.NewReader("config\n"), "test", []string{"php/evil"})
	if err == nil {
		t.Fatal("expected error for extension with path separator")
	}
}
