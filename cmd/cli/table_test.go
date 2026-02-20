package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	timebound "github.com/builder-magic/timebound-iam/timebound/aws"
)

func TestRenderSummary(t *testing.T) {
	tests := []struct {
		name     string
		params   SummaryParams
		contains []string
	}{
		{
			name: "basic fields",
			params: SummaryParams{
				Account: "123456789012",
				Role:    "arn:aws:iam::123456789012:role/timebound-iam-broker",
				TTL:     15 * time.Minute,
				Scopes: []timebound.ServiceScope{
					{Service: "s3", Level: timebound.LevelReadOnly},
				},
			},
			contains: []string{
				"Account", "123456789012",
				"Role", "timebound-iam-broker",
				"TTL", "15m",
				"Scope", "s3:read_only",
			},
		},
		{
			name: "with profile and command",
			params: SummaryParams{
				Account: "123456789012",
				Role:    "arn:aws:iam::123456789012:role/timebound-iam-broker",
				Profile: "dev",
				TTL:     1 * time.Hour,
				Scopes: []timebound.ServiceScope{
					{Service: "s3", Level: timebound.LevelReadOnly},
					{Service: "dynamodb", Level: timebound.LevelFull},
				},
				Command: []string{"aws", "s3", "ls"},
			},
			contains: []string{
				"Profile", "dev",
				"TTL", "1h",
				"s3:read_only",
				"dynamodb:full",
				"Command", "aws s3 ls",
			},
		},
		{
			name: "box drawing characters present",
			params: SummaryParams{
				Account: "123456789012",
				Role:    "arn:aws:iam::123456789012:role/timebound-iam-broker",
				TTL:     30 * time.Minute,
				Scopes: []timebound.ServiceScope{
					{Service: "s3", Level: timebound.LevelReadOnly},
				},
			},
			contains: []string{"┌", "┐", "└", "┘", "│"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			RenderSummary(&buf, tt.params)
			output := buf.String()

			for _, s := range tt.contains {
				if !strings.Contains(output, s) {
					t.Errorf("output missing %q:\n%s", s, output)
				}
			}
		})
	}
}

func TestFormatTTL(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{15 * time.Minute, "15m"},
		{30 * time.Minute, "30m"},
		{1 * time.Hour, "1h"},
		{2 * time.Hour, "2h"},
		{90 * time.Minute, "1h30m"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatTTL(tt.d)
			if got != tt.want {
				t.Errorf("formatTTL(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}
