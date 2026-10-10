package logging

import (
	"regexp"
	"strings"
)

// Redaction placeholder used in place of any secret-looking token.
const redacted = "[REDACTED]"

var (
	// UAPI and awg-quick key lines: the value is removed entirely.
	reSecretAssign = regexp.MustCompile(`(?i)\b(private[_ ]?key|preshared[_ ]?key|header[_ ]?protection[_ ]?key|privatekey|presharedkey|headerprotectionkey)\s*[=:]\s*\S+`)

	// A 32 byte key in hex, which is what the amneziawg-go UAPI uses.
	reHexKey = regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)

	// A 32 byte key in base64, which is what .conf files use.
	reBase64Key = regexp.MustCompile(`\b[A-Za-z0-9+/]{43}=`)
)

// Redact removes anything that could be WireGuard/AmneziaWG key material from s.
//
// It is applied unconditionally to every line AWGSocks logs, including lines
// produced by the embedded AmneziaWG device at DEBUG level. Three independent
// patterns are used so that a key leaks only if it is neither on a labelled
// assignment line, nor hex-encoded, nor base64-encoded.
func Redact(s string) string {
	if s == "" {
		return s
	}
	s = reSecretAssign.ReplaceAllStringFunc(s, func(m string) string {
		i := strings.IndexAny(m, "=:")
		if i < 0 {
			return redacted
		}
		return m[:i+1] + redacted
	})
	s = reHexKey.ReplaceAllString(s, redacted)
	s = reBase64Key.ReplaceAllString(s, redacted)
	return s
}

// RedactUAPI strips every secret-bearing line from a UAPI document so that the
// remainder can be logged or returned over IPC. Lines whose key is a secret are
// dropped entirely rather than blanked, matching what `wg showconf` does for
// unprivileged callers.
func RedactUAPI(uapi string) string {
	var b strings.Builder
	for _, line := range strings.Split(uapi, "\n") {
		key, _, ok := strings.Cut(line, "=")
		if ok {
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "private_key", "preshared_key", "header_protection_key":
				b.WriteString(key)
				b.WriteString("=")
				b.WriteString(redacted)
				b.WriteString("\n")
				continue
			}
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}
