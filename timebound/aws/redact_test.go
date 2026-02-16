package timebound

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		prefixLen int
		suffixLen int
		want      string
	}{
		// Normal cases: prefix + suffix
		{
			name:      "normal prefix and suffix",
			input:     "abcdefghij",
			prefixLen: 3,
			suffixLen: 3,
			want:      "abc...hij",
		},
		{
			name:      "typical secret key",
			input:     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			prefixLen: 4,
			suffixLen: 4,
			want:      "wJal...EKEY",
		},

		// Normal cases: prefix only (suffixLen == 0)
		{
			name:      "prefix only",
			input:     "FwoGZXIvYXdzEBYaDHexampletoken",
			prefixLen: 20,
			suffixLen: 0,
			want:      "FwoGZXIvYXdzEBYaDHex...",
		},
		{
			name:      "prefix only short prefix",
			input:     "abcdefghij",
			prefixLen: 3,
			suffixLen: 0,
			want:      "abc...",
		},

		// Empty string
		{
			name:      "empty string",
			input:     "",
			prefixLen: 4,
			suffixLen: 4,
			want:      "",
		},
		{
			name:      "empty string prefix only",
			input:     "",
			prefixLen: 20,
			suffixLen: 0,
			want:      "",
		},

		// String shorter than prefix+suffix: fully masked
		{
			name:      "shorter than prefix plus suffix",
			input:     "abc",
			prefixLen: 4,
			suffixLen: 4,
			want:      "***",
		},
		{
			name:      "one char with large prefix and suffix",
			input:     "x",
			prefixLen: 10,
			suffixLen: 10,
			want:      "*",
		},
		{
			name:      "two chars with prefix 4 suffix 4",
			input:     "ab",
			prefixLen: 4,
			suffixLen: 4,
			want:      "**",
		},

		// String exactly equal to prefix+suffix: fully masked
		// (no middle portion to redact, so masking is the safe choice)
		{
			name:      "exactly prefix plus suffix length",
			input:     "abcdefgh",
			prefixLen: 4,
			suffixLen: 4,
			want:      "********",
		},
		{
			name:      "exactly prefix length with suffix zero",
			input:     "abc",
			prefixLen: 3,
			suffixLen: 0,
			want:      "***",
		},

		// String one char longer than prefix+suffix: redaction kicks in
		{
			name:      "one char longer than prefix plus suffix",
			input:     "abcdefghi",
			prefixLen: 4,
			suffixLen: 4,
			want:      "abcd...fghi",
		},
		{
			name:      "one char longer than prefix with suffix zero",
			input:     "abcd",
			prefixLen: 3,
			suffixLen: 0,
			want:      "abc...",
		},

		// Zero prefix and suffix
		{
			name:      "zero prefix zero suffix",
			input:     "secret",
			prefixLen: 0,
			suffixLen: 0,
			want:      "******",
		},
		{
			name:      "zero prefix with suffix",
			input:     "abcdefghij",
			prefixLen: 0,
			suffixLen: 3,
			want:      "...hij",
		},
		{
			name:      "zero prefix with suffix on short string",
			input:     "ab",
			prefixLen: 0,
			suffixLen: 3,
			want:      "**",
		},

		// Single character string
		{
			name:      "single char prefix 1 suffix 0",
			input:     "a",
			prefixLen: 1,
			suffixLen: 0,
			want:      "*",
		},
		{
			name:      "single char prefix 0 suffix 1",
			input:     "a",
			prefixLen: 0,
			suffixLen: 1,
			want:      "*",
		},
		{
			name:      "single char prefix 1 suffix 1",
			input:     "a",
			prefixLen: 1,
			suffixLen: 1,
			want:      "*",
		},

		// Large prefix/suffix values on normal string
		{
			name:      "prefix larger than string",
			input:     "hello",
			prefixLen: 100,
			suffixLen: 0,
			want:      "*****",
		},
		{
			name:      "suffix larger than string",
			input:     "hello",
			prefixLen: 0,
			suffixLen: 100,
			want:      "*****",
		},
		{
			name:      "both larger than string",
			input:     "hello",
			prefixLen: 100,
			suffixLen: 100,
			want:      "*****",
		},

		// Realistic AWS credential sizes
		{
			name:      "access key id 20 chars show first 4 last 4",
			input:     "AKIAIOSFODNN7EXAMPLE",
			prefixLen: 4,
			suffixLen: 4,
			want:      "AKIA...MPLE",
		},
		{
			name:      "secret key 40 chars show first 4 last 4",
			input:     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			prefixLen: 4,
			suffixLen: 4,
			want:      "wJal...EKEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.input, tt.prefixLen, tt.suffixLen)
			if got != tt.want {
				t.Errorf("Redact(%q, %d, %d) = %q, want %q",
					tt.input, tt.prefixLen, tt.suffixLen, got, tt.want)
			}
		})
	}
}

func TestRedactNeverLeaksFullValue(t *testing.T) {
	inputs := []string{
		"a",
		"ab",
		"abc",
		"abcdefgh",
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	configs := []struct {
		prefix int
		suffix int
	}{
		{0, 0},
		{1, 0},
		{0, 1},
		{1, 1},
		{4, 4},
		{10, 10},
		{100, 100},
	}

	for _, input := range inputs {
		for _, cfg := range configs {
			got := Redact(input, cfg.prefix, cfg.suffix)
			if got == input {
				t.Errorf("Redact(%q, %d, %d) = %q, leaked full value",
					input, cfg.prefix, cfg.suffix, got)
			}
		}
	}
}

func TestRedactOutputNeverContainsFullSecret(t *testing.T) {
	secret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	got := Redact(secret, 4, 4)
	if strings.Contains(got, secret) {
		t.Errorf("redacted output contains the full secret")
	}
}

func TestRedactMaskedPortionLength(t *testing.T) {
	tests := []struct {
		input     string
		prefixLen int
		suffixLen int
	}{
		{"abc", 4, 4},
		{"ab", 10, 10},
		{"x", 1, 1},
		{"hello", 100, 100},
	}

	for _, tt := range tests {
		got := Redact(tt.input, tt.prefixLen, tt.suffixLen)
		if len(got) != len(tt.input) {
			t.Errorf("Redact(%q, %d, %d) = %q (len %d), want mask of len %d",
				tt.input, tt.prefixLen, tt.suffixLen, got, len(got), len(tt.input))
		}
		for _, c := range got {
			if c != '*' {
				t.Errorf("Redact(%q, %d, %d) = %q, expected all asterisks",
					tt.input, tt.prefixLen, tt.suffixLen, got)
				break
			}
		}
	}
}

func TestRedactEmptyStringAlwaysEmpty(t *testing.T) {
	configs := []struct {
		prefix int
		suffix int
	}{
		{0, 0},
		{1, 0},
		{0, 1},
		{4, 4},
		{100, 100},
	}

	for _, cfg := range configs {
		got := Redact("", cfg.prefix, cfg.suffix)
		if got != "" {
			t.Errorf("Redact(\"\", %d, %d) = %q, want empty",
				cfg.prefix, cfg.suffix, got)
		}
	}
}
