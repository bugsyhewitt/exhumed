// Package extract provides format-aware content parsers that extract findings
// (credentials, keys, usernames, config values) from confirmed-readable files.
// Parsers are dispatched by the entry's parser hint; unknown hints fall back to
// the generic-secrets sweep.
package extract

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// FindingType categorises what was extracted.
type FindingType string

const (
	FindingTypeUser      FindingType = "user"
	FindingTypeSecret    FindingType = "secret"
	FindingTypeSSHKey    FindingType = "ssh-key"
	FindingTypeGitConfig FindingType = "git-config"
	FindingTypePath      FindingType = "path"
)

// Finding is one piece of extracted intelligence.
type Finding struct {
	// Type classifies the finding.
	Type FindingType
	// Key is the label (e.g. key name, username, kind of secret).
	Key string
	// Value is the raw extracted value. May be empty for presence-only findings.
	Value string
	// Redacted marks whether Value should be hidden in default output.
	Redacted bool
	// Source is the file path this finding came from.
	Source string
	// Confidence is a 0–1 estimate of how likely this is a real finding.
	Confidence float32
	// Extra holds parser-specific metadata (e.g. home dir, shell for users).
	Extra map[string]string
	// Depth tracks which generation of follow-on chain produced this finding.
	Depth int
}

// DisplayValue returns the value as it should be shown in output.
// If showSecrets is false, secret values are partially redacted.
func (f Finding) DisplayValue(showSecrets bool) string {
	if !f.Redacted || showSecrets {
		return f.Value
	}
	return redact(f.Value)
}

// redact partially hides a secret value, showing only first/last 3 chars.
func redact(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:3] + "***" + s[len(s)-3:]
}

// Parse dispatches to the appropriate parser based on hint and returns all findings.
// Unknown hints fall back to the generic-secrets sweep.
func Parse(hint string, body []byte, source string) []Finding {
	switch hint {
	case "unix-passwd":
		return parsePasswd(body, source)
	case "env", "ini-config":
		return parseKeyValue(body, source)
	case "ssh-key":
		return parseSSHKey(body, source)
	case "generic-secrets":
		return parseGenericSecrets(body, source)
	default:
		// Fallback: run generic sweep on any unrecognised hint.
		return parseGenericSecrets(body, source)
	}
}

// ── unix-passwd ───────────────────────────────────────────────────────────────

func parsePasswd(body []byte, source string) []Finding {
	var findings []Finding
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		username := parts[0]
		home := parts[5]
		shell := parts[6]
		if username == "" {
			continue
		}
		findings = append(findings, Finding{
			Type:       FindingTypeUser,
			Key:        username,
			Source:     source,
			Confidence: 0.95,
			Extra: map[string]string{
				"home":  home,
				"shell": shell,
				"uid":   parts[2],
				"gid":   parts[3],
			},
		})
	}
	return findings
}

// ── env / ini-config ──────────────────────────────────────────────────────────

// secretKeyRE matches KEY names that suggest credential or secret content.
var secretKeyRE = regexp.MustCompile(`(?i)(password|passwd|secret|key|token|auth|cred|api_key|access_key|private)`)

func parseKeyValue(body []byte, source string) []Finding {
	var findings []Finding
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		sep := strings.IndexByte(line, '=')
		if sep < 0 {
			// Try colon separator for ini-style values.
			sep = strings.IndexByte(line, ':')
			if sep < 0 {
				continue
			}
		}
		key := strings.TrimSpace(line[:sep])
		value := strings.TrimSpace(line[sep+1:])
		if key == "" || value == "" {
			continue
		}
		if !secretKeyRE.MatchString(key) {
			continue
		}
		findings = append(findings, Finding{
			Type:       FindingTypeSecret,
			Key:        key,
			Value:      value,
			Redacted:   true,
			Source:     source,
			Confidence: 0.8,
		})
	}
	return findings
}

// ── ssh-key ───────────────────────────────────────────────────────────────────

func parseSSHKey(body []byte, source string) []Finding {
	s := string(body)
	if strings.Contains(s, "PRIVATE KEY") {
		return []Finding{{
			Type:       FindingTypeSSHKey,
			Key:        "private-key",
			Value:      s,
			Redacted:   true,
			Source:     source,
			Confidence: 0.99,
		}}
	}
	return nil
}

// ── generic-secrets ───────────────────────────────────────────────────────────

var (
	awsKeyRE       = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	privateKeyRE   = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	bearerTokenRE  = regexp.MustCompile(`(?i)bearer\s+([A-Za-z0-9._\-]{20,})`)
	jwtRE          = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)
	dbConnStringRE = regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis)://[^\s'"]+`)
	genericPassRE  = regexp.MustCompile(`(?i)(password|passwd|secret)\s*[=:]\s*\S+`)
)

func parseGenericSecrets(body []byte, source string) []Finding {
	s := string(body)
	var findings []Finding

	if m := awsKeyRE.FindString(s); m != "" {
		findings = append(findings, Finding{
			Type:       FindingTypeSecret,
			Key:        "AWS_ACCESS_KEY_ID",
			Value:      m,
			Redacted:   true,
			Source:     source,
			Confidence: 0.95,
		})
	}

	if privateKeyRE.MatchString(s) {
		findings = append(findings, Finding{
			Type:       FindingTypeSSHKey,
			Key:        "PRIVATE_KEY",
			Value:      s,
			Redacted:   true,
			Source:     source,
			Confidence: 0.99,
		})
	}

	if ms := bearerTokenRE.FindStringSubmatch(s); len(ms) > 1 {
		findings = append(findings, Finding{
			Type:       FindingTypeSecret,
			Key:        "BEARER_TOKEN",
			Value:      ms[1],
			Redacted:   true,
			Source:     source,
			Confidence: 0.8,
		})
	}

	if m := jwtRE.FindString(s); m != "" {
		findings = append(findings, Finding{
			Type:       FindingTypeSecret,
			Key:        "JWT_TOKEN",
			Value:      m,
			Redacted:   true,
			Source:     source,
			Confidence: 0.85,
		})
	}

	if m := dbConnStringRE.FindString(s); m != "" {
		findings = append(findings, Finding{
			Type:       FindingTypeSecret,
			Key:        "DB_CONNECTION_STRING",
			Value:      m,
			Redacted:   true,
			Source:     source,
			Confidence: 0.9,
		})
	}

	for _, m := range genericPassRE.FindAllString(s, -1) {
		parts := strings.SplitN(m, "=", 2)
		if len(parts) < 2 {
			parts = strings.SplitN(m, ":", 2)
		}
		if len(parts) < 2 {
			continue
		}
		findings = append(findings, Finding{
			Type:       FindingTypeSecret,
			Key:        strings.TrimSpace(parts[0]),
			Value:      strings.TrimSpace(parts[1]),
			Redacted:   true,
			Source:     source,
			Confidence: 0.7,
		})
	}

	return findings
}
