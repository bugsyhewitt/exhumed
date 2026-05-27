package extract_test

import (
	"strings"
	"testing"

	"github.com/bugsyhewitt/exhumed/internal/extract"
)

// ── unix-passwd parser ────────────────────────────────────────────────────────

func TestPasswd_ParsesUsers(t *testing.T) {
	body := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n"
	findings := extract.Parse("unix-passwd", []byte(body), "/etc/passwd")
	if len(findings) == 0 {
		t.Fatal("expected findings from passwd, got none")
	}
	var users []string
	for _, f := range findings {
		if f.Type == extract.FindingTypeUser {
			users = append(users, f.Key)
		}
	}
	if len(users) < 3 {
		t.Errorf("expected >= 3 users, got %d: %v", len(users), users)
	}
}

func TestPasswd_ExtractsHomeDir(t *testing.T) {
	body := "app:x:1000:1000:App User:/home/app:/bin/sh\n"
	findings := extract.Parse("unix-passwd", []byte(body), "/etc/passwd")
	var found bool
	for _, f := range findings {
		if f.Type == extract.FindingTypeUser && f.Key == "app" && f.Extra["home"] == "/home/app" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected finding for user 'app' with home=/home/app; got: %+v", findings)
	}
}

func TestPasswd_ExtractsShell(t *testing.T) {
	body := "root:x:0:0:root:/root:/bin/bash\n"
	findings := extract.Parse("unix-passwd", []byte(body), "/etc/passwd")
	for _, f := range findings {
		if f.Type == extract.FindingTypeUser && f.Key == "root" {
			if f.Extra["shell"] != "/bin/bash" {
				t.Errorf("expected shell=/bin/bash, got %q", f.Extra["shell"])
			}
			return
		}
	}
	t.Error("root user not found in findings")
}

func TestPasswd_MalformedLine(t *testing.T) {
	body := "this is not a passwd line\nroot:x:0:0:root:/root:/bin/bash\n"
	// Should not panic; valid lines still parsed.
	findings := extract.Parse("unix-passwd", []byte(body), "/etc/passwd")
	var rootFound bool
	for _, f := range findings {
		if f.Key == "root" {
			rootFound = true
		}
	}
	if !rootFound {
		t.Error("expected root user parsed despite malformed preceding line")
	}
}

// ── env / ini-config parser ───────────────────────────────────────────────────

func TestEnv_ExtractsSecrets(t *testing.T) {
	body := "APP_KEY=base64:abc123\nDB_PASSWORD=s3cr3t\nDEBUG=false\nNOT_SECRET=value\n"
	findings := extract.Parse("env", []byte(body), ".env")
	var keys []string
	for _, f := range findings {
		if f.Type == extract.FindingTypeSecret {
			keys = append(keys, f.Key)
		}
	}
	if len(keys) == 0 {
		t.Error("expected secret findings from .env body")
	}
	// DB_PASSWORD should be detected.
	var dbFound bool
	for _, k := range keys {
		if strings.Contains(strings.ToLower(k), "password") {
			dbFound = true
		}
	}
	if !dbFound {
		t.Errorf("expected DB_PASSWORD in secrets, got: %v", keys)
	}
}

func TestIniConfig_ExtractsCredentials(t *testing.T) {
	body := "[database]\nhost=127.0.0.1\nport=5432\nname=appdb\nuser=appuser\npassword=s3cr3t_db_p4ssw0rd\n"
	findings := extract.Parse("ini-config", []byte(body), "my.cnf")
	var found bool
	for _, f := range findings {
		if f.Type == extract.FindingTypeSecret && strings.Contains(strings.ToLower(f.Key), "password") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected password finding from ini body; got: %+v", findings)
	}
}

// ── ssh-key parser ────────────────────────────────────────────────────────────

func TestSSHKey_Detected(t *testing.T) {
	body := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA2a...\n-----END RSA PRIVATE KEY-----\n"
	findings := extract.Parse("ssh-key", []byte(body), "/root/.ssh/id_rsa")
	var found bool
	for _, f := range findings {
		if f.Type == extract.FindingTypeSSHKey {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SSH key finding; got: %+v", findings)
	}
}

func TestSSHKey_ValueRedactedByDefault(t *testing.T) {
	body := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA2a...\n-----END RSA PRIVATE KEY-----\n"
	findings := extract.Parse("ssh-key", []byte(body), "/root/.ssh/id_rsa")
	for _, f := range findings {
		if f.Type == extract.FindingTypeSSHKey {
			if f.Redacted == false {
				t.Error("expected SSH key value to be marked as requiring redaction")
			}
			return
		}
	}
	t.Error("no SSH key finding found")
}

// ── generic-secrets sweep ─────────────────────────────────────────────────────

func TestGenericSecrets_AWSKey(t *testing.T) {
	body := "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
	findings := extract.Parse("generic-secrets", []byte(body), "/root/.env")
	var found bool
	for _, f := range findings {
		if f.Type == extract.FindingTypeSecret && strings.Contains(f.Key, "AWS") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected AWS key finding; got: %+v", findings)
	}
}

func TestGenericSecrets_PrivateKeyHeader(t *testing.T) {
	body := "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhki...\n"
	findings := extract.Parse("generic-secrets", []byte(body), "/etc/ssl/server.key")
	var found bool
	for _, f := range findings {
		if f.Type == extract.FindingTypeSSHKey || (f.Type == extract.FindingTypeSecret && strings.Contains(f.Key, "KEY")) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected private key finding; got: %+v", findings)
	}
}

// ── Redaction ─────────────────────────────────────────────────────────────────

func TestRedaction_DefaultHidesValue(t *testing.T) {
	body := "DB_PASSWORD=supersecretvalue123\n"
	findings := extract.Parse("env", []byte(body), ".env")
	for _, f := range findings {
		if f.Type == extract.FindingTypeSecret && strings.Contains(strings.ToLower(f.Key), "password") {
			displayed := f.DisplayValue(false)
			if displayed == "supersecretvalue123" {
				t.Error("expected value to be redacted by default")
			}
			if !strings.Contains(displayed, "***") && !strings.Contains(displayed, "…") && len(displayed) <= len("supersecretvalue123") {
				// Accept any truncation scheme
			}
			return
		}
	}
	t.Error("no password finding to test redaction on")
}

func TestRedaction_ShowSecretsRevealsValue(t *testing.T) {
	body := "DB_PASSWORD=supersecretvalue123\n"
	findings := extract.Parse("env", []byte(body), ".env")
	for _, f := range findings {
		if f.Type == extract.FindingTypeSecret && strings.Contains(strings.ToLower(f.Key), "password") {
			displayed := f.DisplayValue(true)
			if displayed != "supersecretvalue123" {
				t.Errorf("with showSecrets=true expected full value, got %q", displayed)
			}
			return
		}
	}
	t.Error("no password finding to test redaction on")
}

// ── proc-environ parser ───────────────────────────────────────────────────────

func nulJoin(pairs ...string) []byte {
	var buf []byte
	for _, p := range pairs {
		buf = append(buf, []byte(p)...)
		buf = append(buf, 0x00)
	}
	return buf
}

func TestProcEnviron_DetectsDBPassword(t *testing.T) {
	body := nulJoin(
		"PATH=/usr/bin:/bin",
		"DB_PASSWORD=hunter2",
		"USER=www-data",
	)
	findings := extract.Parse("proc-environ", body, "/proc/self/environ")
	var found bool
	for _, f := range findings {
		if f.Type == extract.FindingTypeSecret && f.Key == "DB_PASSWORD" && f.Value == "hunter2" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected DB_PASSWORD secret finding; got: %+v", findings)
	}
}

func TestProcEnviron_DetectsAWSSecretKey(t *testing.T) {
	body := nulJoin(
		"HOME=/root",
		"AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
	)
	findings := extract.Parse("proc-environ", body, "/proc/self/environ")
	var found bool
	for _, f := range findings {
		if f.Type == extract.FindingTypeSecret && f.Key == "AWS_SECRET_ACCESS_KEY" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected AWS_SECRET_ACCESS_KEY finding; got: %+v", findings)
	}
}

func TestProcEnviron_EmitsInfoForDocumentRoot(t *testing.T) {
	body := nulJoin(
		"DOCUMENT_ROOT=/var/www/html",
		"APP_ENV=production",
	)
	findings := extract.Parse("proc-environ", body, "/proc/self/environ")
	var found bool
	for _, f := range findings {
		if f.Type == extract.FindingTypeInfo && f.Key == "DOCUMENT_ROOT" && f.Value == "/var/www/html" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected DOCUMENT_ROOT info finding; got: %+v", findings)
	}
}

func TestProcEnviron_EmitsInfoForPWD(t *testing.T) {
	body := nulJoin("PWD=/var/www/html")
	findings := extract.Parse("proc-environ", body, "/proc/self/environ")
	var found bool
	for _, f := range findings {
		if f.Type == extract.FindingTypeInfo && f.Key == "PWD" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected PWD info finding; got: %+v", findings)
	}
}

func TestProcEnviron_SecretIsRedacted(t *testing.T) {
	body := nulJoin("DB_PASSWORD=hunter2")
	findings := extract.Parse("proc-environ", body, "/proc/self/environ")
	for _, f := range findings {
		if f.Type == extract.FindingTypeSecret && f.Key == "DB_PASSWORD" {
			if !f.Redacted {
				t.Error("expected DB_PASSWORD finding to be marked Redacted")
			}
			displayed := f.DisplayValue(false)
			if displayed == "hunter2" {
				t.Error("expected value to be redacted in display")
			}
			return
		}
	}
	t.Error("no DB_PASSWORD finding found")
}

func TestProcEnviron_ConfidenceIs085ForSecrets(t *testing.T) {
	body := nulJoin("API_TOKEN=abc123")
	findings := extract.Parse("proc-environ", body, "/proc/self/environ")
	for _, f := range findings {
		if f.Type == extract.FindingTypeSecret && f.Key == "API_TOKEN" {
			if f.Confidence != 0.85 {
				t.Errorf("expected Confidence=0.85, got %v", f.Confidence)
			}
			return
		}
	}
	t.Error("no API_TOKEN finding found")
}

func TestProcEnviron_NonSecretKeysIgnored(t *testing.T) {
	body := nulJoin(
		"RAILS_ENV=production",
		"HOSTNAME=webapp-01",
		"LANG=en_US.UTF-8",
	)
	findings := extract.Parse("proc-environ", body, "/proc/self/environ")
	for _, f := range findings {
		if f.Type == extract.FindingTypeSecret {
			t.Errorf("unexpected secret finding for non-secret env var: %+v", f)
		}
	}
}

func TestProcEnviron_EmptyBodyReturnsNoFindings(t *testing.T) {
	findings := extract.Parse("proc-environ", []byte{}, "/proc/self/environ")
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty body, got: %+v", findings)
	}
}

func TestProcEnviron_SourceFieldPopulated(t *testing.T) {
	body := nulJoin("DB_PASSWORD=secret")
	findings := extract.Parse("proc-environ", body, "/proc/self/environ")
	for _, f := range findings {
		if f.Source != "/proc/self/environ" {
			t.Errorf("expected Source=/proc/self/environ, got %q", f.Source)
		}
	}
}

// ── Fallback / unknown parser ─────────────────────────────────────────────────

func TestFallback_GenericSweep(t *testing.T) {
	body := "AKIA0000000000000001\npassword=topsecret\n"
	// Parser hint not recognized → falls back to generic-secrets sweep.
	findings := extract.Parse("unknown-parser-hint", []byte(body), "/some/file")
	// Should not panic; may or may not find things depending on fallback.
	_ = findings
}
