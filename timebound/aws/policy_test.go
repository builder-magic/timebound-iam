package aws

import (
	"testing"

	"github.com/builder-magic/timebound-iam/timebound/core"
)

func TestGetPolicyARN(t *testing.T) {
	tests := []struct {
		name      string
		service   string
		level     string
		wantARN   string
		wantError bool
	}{
		{
			name:    "s3 read only",
			service: "s3",
			level:   core.LevelReadOnly,
			wantARN: "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
		},
		{
			name:    "s3 full access",
			service: "s3",
			level:   core.LevelFull,
			wantARN: "arn:aws:iam::aws:policy/AmazonS3FullAccess",
		},
		{
			name:    "lambda read only",
			service: "lambda",
			level:   core.LevelReadOnly,
			wantARN: "arn:aws:iam::aws:policy/AWSLambda_ReadOnlyAccess",
		},
		{
			name:    "dynamodb full access",
			service: "dynamodb",
			level:   core.LevelFull,
			wantARN: "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess",
		},
		{
			name:    "uppercase service name",
			service: "S3",
			level:   core.LevelReadOnly,
			wantARN: "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
		},
		{
			name:    "mixed case service name",
			service: "DynamoDB",
			level:   core.LevelFull,
			wantARN: "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess",
		},
		{
			name:    "leading and trailing spaces",
			service: "  lambda  ",
			level:   core.LevelReadOnly,
			wantARN: "arn:aws:iam::aws:policy/AWSLambda_ReadOnlyAccess",
		},
		{
			name:      "unknown service",
			service:   "nonexistent",
			level:     core.LevelReadOnly,
			wantError: true,
		},
		{
			name:      "invalid level",
			service:   "s3",
			level:     "admin",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			arn, err := GetPolicyARN(tt.service, tt.level)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if arn != tt.wantARN {
				t.Errorf("got ARN %q, want %q", arn, tt.wantARN)
			}
		})
	}
}

func TestGetPolicyARNs(t *testing.T) {
	tests := []struct {
		name      string
		services  []string
		level     string
		wantCount int
		wantError bool
	}{
		{
			name:      "multiple valid services",
			services:  []string{"s3", "dynamodb", "lambda"},
			level:     core.LevelReadOnly,
			wantCount: 3,
		},
		{
			name:      "single service",
			services:  []string{"ec2"},
			level:     core.LevelFull,
			wantCount: 1,
		},
		{
			name:      "one unknown service fails all",
			services:  []string{"s3", "nonexistent"},
			level:     core.LevelReadOnly,
			wantError: true,
		},
		{
			name:      "mixed case deduplicated",
			services:  []string{"s3", "S3", " s3 "},
			level:     core.LevelReadOnly,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			arns, err := GetPolicyARNs(tt.services, tt.level)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(arns) != tt.wantCount {
				t.Errorf("got %d ARNs, want %d", len(arns), tt.wantCount)
			}
		})
	}
}

func TestListServices(t *testing.T) {
	services := ListServices()
	if len(services) == 0 {
		t.Fatal("expected at least one service")
	}

	// Verify sorted order
	for i := 1; i < len(services); i++ {
		if services[i].Name <= services[i-1].Name {
			t.Errorf("services not sorted: %s comes after %s", services[i].Name, services[i-1].Name)
		}
	}

	// Verify every service has at least one level
	for _, svc := range services {
		if len(svc.Levels) == 0 {
			t.Errorf("service %s has no access levels", svc.Name)
		}
	}
}

func TestValidateServices(t *testing.T) {
	tests := []struct {
		name      string
		services  []string
		wantError bool
	}{
		{
			name:     "all valid",
			services: []string{"s3", "ec2", "lambda"},
		},
		{
			name:      "one invalid",
			services:  []string{"s3", "bogus"},
			wantError: true,
		},
		{
			name:      "all invalid",
			services:  []string{"foo", "bar"},
			wantError: true,
		},
		{
			name:      "empty list",
			services:  []string{},
			wantError: true,
		},
		{
			name:     "uppercase names normalized",
			services: []string{"S3", "EC2", " Lambda "},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateServices(tt.services)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
