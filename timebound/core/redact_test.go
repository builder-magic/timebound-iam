package core

import "testing"

func TestRedact(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		prefixLen int
		suffixLen int
		want      string
	}{
		{
			name:      "empty string",
			input:     "",
			prefixLen: 4,
			suffixLen: 4,
			want:      "",
		},
		{
			name:      "both prefix and suffix",
			input:     "AKIAIOSFODNN7EXAMPLE",
			prefixLen: 4,
			suffixLen: 4,
			want:      "AKIA...MPLE",
		},
		{
			name:      "prefix only",
			input:     "FwoGZXIvYXdzEBYaDH",
			prefixLen: 6,
			suffixLen: 0,
			want:      "FwoGZX...",
		},
		{
			name:      "too short to redact",
			input:     "abc",
			prefixLen: 4,
			suffixLen: 4,
			want:      "***",
		},
		{
			name:      "zero lengths",
			input:     "secret",
			prefixLen: 0,
			suffixLen: 0,
			want:      "******",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.input, tt.prefixLen, tt.suffixLen)
			if got != tt.want {
				t.Errorf("Redact(%q, %d, %d) = %q, want %q", tt.input, tt.prefixLen, tt.suffixLen, got, tt.want)
			}
		})
	}
}
