package timebound

import (
	"testing"
)

func TestSelectServices(t *testing.T) {
	services := []ServiceInfo{
		{Name: "s3"},
		{Name: "ec2"},
		{Name: "lambda"},
		{Name: "dynamodb"},
	}

	tests := []struct {
		name      string
		input     string
		wantLen   int
		wantNames []string
	}{
		{
			name:      "select all",
			input:     "all",
			wantLen:   4,
			wantNames: []string{"s3", "ec2", "lambda", "dynamodb"},
		},
		{
			name:      "select specific",
			input:     "1,3",
			wantLen:   2,
			wantNames: []string{"lambda", "s3"},
		},
		{
			name:      "select with spaces",
			input:     "1, 2, 4",
			wantLen:   3,
			wantNames: []string{"dynamodb", "ec2", "s3"},
		},
		{
			name:    "invalid input ignored",
			input:   "abc,xyz",
			wantLen: 0,
		},
		{
			name:    "out of range ignored",
			input:   "0,5,99",
			wantLen: 0,
		},
		{
			name:      "mixed valid and invalid",
			input:     "1,abc,2",
			wantLen:   2,
			wantNames: []string{"ec2", "s3"},
		},
		{
			name:      "duplicates deduplicated",
			input:     "1,1,1",
			wantLen:   1,
			wantNames: []string{"s3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectServices(services, tt.input)
			if len(got) != tt.wantLen {
				t.Errorf("got %d services, want %d: %v", len(got), tt.wantLen, got)
				return
			}
			for i, name := range tt.wantNames {
				if i < len(got) && got[i] != name {
					t.Errorf("service[%d] = %q, want %q", i, got[i], name)
				}
			}
		})
	}
}

func TestBuildTrustPolicy(t *testing.T) {
	policy := buildTrustPolicy("123456789012")
	if policy.Version != "2012-10-17" {
		t.Errorf("Version = %q, want 2012-10-17", policy.Version)
	}
	if len(policy.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(policy.Statement))
	}
	stmt := policy.Statement[0]
	if stmt.Effect != "Allow" {
		t.Errorf("Effect = %q, want Allow", stmt.Effect)
	}
	if stmt.Principal == nil || stmt.Principal.AWS != "arn:aws:iam::123456789012:root" {
		t.Error("unexpected principal")
	}
}

func TestBuildInlinePolicy(t *testing.T) {
	policy := buildInlinePolicy([]string{"s3", "dynamodb", "stepfunctions"})
	if len(policy.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(policy.Statement))
	}

	actions, ok := policy.Statement[0].Action.([]string)
	if !ok {
		t.Fatal("expected Action to be []string")
	}

	// Should include dynamodb:*, s3:*, states:*, sts:AssumeRole (sorted)
	expected := []string{"dynamodb:*", "s3:*", "states:*", "sts:AssumeRole"}
	if len(actions) != len(expected) {
		t.Fatalf("got %d actions, want %d: %v", len(actions), len(expected), actions)
	}
	for i, want := range expected {
		if actions[i] != want {
			t.Errorf("action[%d] = %q, want %q", i, actions[i], want)
		}
	}
}
