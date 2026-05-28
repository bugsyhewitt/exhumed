package oob

import (
	"strings"
	"testing"
)

func TestGenerate_DefaultTechniquesAndOrder(t *testing.T) {
	got, err := Generate(Options{Domain: "abc123.oast.fun"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	wantOrder := []Technique{TechniqueSMB, TechniqueHTTP, TechniqueHTTPS, TechniqueDNS}
	if len(got) != len(wantOrder) {
		t.Fatalf("got %d payloads, want %d", len(got), len(wantOrder))
	}
	for i, w := range wantOrder {
		if got[i].Technique != w {
			t.Errorf("payload %d: technique = %q, want %q", i, got[i].Technique, w)
		}
		if got[i].Value == "" {
			t.Errorf("payload %d (%s): empty value", i, got[i].Technique)
		}
		if got[i].Note == "" {
			t.Errorf("payload %d (%s): empty note", i, got[i].Technique)
		}
	}
}

func TestGenerate_DefaultValues(t *testing.T) {
	got, err := Generate(Options{Domain: "c.example.com"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	byTech := map[Technique]Payload{}
	for _, p := range got {
		byTech[p.Technique] = p
	}

	if v := byTech[TechniqueSMB].Value; v != `\\c.example.com\exhumed` {
		t.Errorf("smb value = %q, want default share", v)
	}
	if v := byTech[TechniqueHTTP].Value; v != "http://c.example.com/exhumed-oob" {
		t.Errorf("http value = %q, want default path", v)
	}
	if v := byTech[TechniqueHTTPS].Value; v != "https://c.example.com/exhumed-oob" {
		t.Errorf("https value = %q", v)
	}
	if v := byTech[TechniqueDNS].Value; v != `\\c.example.com\` {
		t.Errorf("dns value = %q, want bare UNC host", v)
	}
}

func TestGenerate_CustomShareAndPath(t *testing.T) {
	got, err := Generate(Options{Domain: "c.example.com", Share: "data", Path: "/beacon/x"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	byTech := map[Technique]Payload{}
	for _, p := range got {
		byTech[p.Technique] = p
	}
	if v := byTech[TechniqueSMB].Value; v != `\\c.example.com\data` {
		t.Errorf("smb value = %q, want custom share", v)
	}
	// Leading slash on Path is stripped before joining.
	if v := byTech[TechniqueHTTP].Value; v != "http://c.example.com/beacon/x" {
		t.Errorf("http value = %q, want custom path with leading slash stripped", v)
	}
}

func TestGenerate_LabelMode(t *testing.T) {
	got, err := Generate(Options{Domain: "c.example.com", Label: true})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	byTech := map[Technique]Payload{}
	for _, p := range got {
		byTech[p.Technique] = p
	}

	// HTTP/HTTPS/DNS get a per-technique subdomain label.
	if v := byTech[TechniqueHTTP].Value; !strings.HasPrefix(v, "http://http.c.example.com/") {
		t.Errorf("http labelled value = %q, want http. label", v)
	}
	if got, want := byTech[TechniqueHTTP].Subdomain, "http"; got != want {
		t.Errorf("http subdomain = %q, want %q", got, want)
	}
	if v := byTech[TechniqueHTTPS].Value; !strings.HasPrefix(v, "https://https.c.example.com/") {
		t.Errorf("https labelled value = %q", v)
	}
	if v := byTech[TechniqueDNS].Value; v != `\\dns.c.example.com\` {
		t.Errorf("dns labelled value = %q", v)
	}

	// SMB intentionally does NOT carry a label on the UNC host.
	if got := byTech[TechniqueSMB].Subdomain; got != "" {
		t.Errorf("smb subdomain = %q, want empty (no label on UNC host)", got)
	}
	if v := byTech[TechniqueSMB].Value; v != `\\c.example.com\exhumed` {
		t.Errorf("smb labelled value = %q, want unlabelled host", v)
	}
}

func TestGenerate_InvalidDomain(t *testing.T) {
	cases := []struct {
		name   string
		domain string
	}{
		{"empty", ""},
		{"scheme", "http://c.example.com"},
		{"path", "c.example.com/foo"},
		{"backslash", `c.example.com\share`},
		{"leading dot", ".example.com"},
		{"trailing dot", "example.com."},
		{"no dot", "localhost"},
		{"whitespace", "c.example.com "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Generate(Options{Domain: tc.domain}); err == nil {
				t.Errorf("Generate(%q): expected error, got nil", tc.domain)
			}
		})
	}
}

func TestGenerate_InvalidShare(t *testing.T) {
	if _, err := Generate(Options{Domain: "c.example.com", Share: "a/b"}); err == nil {
		t.Error("expected error for share containing a slash")
	}
	if _, err := Generate(Options{Domain: "c.example.com", Share: `a\b`}); err == nil {
		t.Error("expected error for share containing a backslash")
	}
}

func TestLabelFor_Exhaustive(t *testing.T) {
	want := map[Technique]string{
		TechniqueSMB:   "smb",
		TechniqueHTTP:  "http",
		TechniqueHTTPS: "https",
		TechniqueDNS:   "dns",
	}
	for tech, lbl := range want {
		if got := labelFor(tech); got != lbl {
			t.Errorf("labelFor(%q) = %q, want %q", tech, got, lbl)
		}
	}
	if got := labelFor(Technique("bogus")); got != "oob" {
		t.Errorf("labelFor(bogus) = %q, want fallback %q", got, "oob")
	}
}
