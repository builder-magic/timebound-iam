package timebound

import "strings"

// Redact returns a partially masked version of s, showing only the first
// prefixLen and last suffixLen characters. If s is too short to redact
// meaningfully, it is fully masked to avoid leaking the entire value.
// AWS credential values are ASCII so byte indexing is safe.
func Redact(s string, prefixLen, suffixLen int) string {
	if len(s) == 0 {
		return ""
	}
	if prefixLen+suffixLen == 0 || len(s) <= prefixLen+suffixLen {
		return strings.Repeat("*", len(s))
	}
	if suffixLen == 0 {
		return s[:prefixLen] + "..."
	}
	return s[:prefixLen] + "..." + s[len(s)-suffixLen:]
}
