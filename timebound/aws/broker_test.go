package timebound

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// mockSTSClient implements STSClient for testing.
type mockSTSClient struct {
	getCallerIdentityFn func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
	assumeRoleFn        func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

func (m *mockSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return m.getCallerIdentityFn(ctx, params, optFns...)
}

func (m *mockSTSClient) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	return m.assumeRoleFn(ctx, params, optFns...)
}

func newTestBroker(t *testing.T, mock *mockSTSClient) *Broker {
	t.Helper()
	broker, err := NewBrokerWithClient(context.Background(), mock)
	if err != nil {
		t.Fatalf("NewBrokerWithClient: %v", err)
	}
	return broker
}

func defaultMock() *mockSTSClient {
	expiration := time.Now().Add(30 * time.Minute)
	return &mockSTSClient{
		getCallerIdentityFn: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: aws.String("123456789012"),
				Arn:     aws.String("arn:aws:iam::123456789012:user/testuser"),
			}, nil
		},
		assumeRoleFn: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			return &sts.AssumeRoleOutput{
				Credentials: &ststypes.Credentials{
					AccessKeyId:     aws.String("AKIAIOSFODNN7EXAMPLE"),
					SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
					SessionToken:    aws.String("FwoGZXIvYXdzEBYaDH..."),
					Expiration:      aws.Time(expiration),
				},
			}, nil
		},
	}
}

func TestNewBrokerWithClient(t *testing.T) {
	mock := defaultMock()
	broker := newTestBroker(t, mock)

	if broker.AccountID() != "123456789012" {
		t.Errorf("AccountID = %q, want %q", broker.AccountID(), "123456789012")
	}
	if broker.BrokerRoleARN() != "arn:aws:iam::123456789012:role/timebound-iam-broker" {
		t.Errorf("BrokerRoleARN = %q, want %q", broker.BrokerRoleARN(), "arn:aws:iam::123456789012:role/timebound-iam-broker")
	}
}

func TestNewBrokerWithClientError(t *testing.T) {
	mock := &mockSTSClient{
		getCallerIdentityFn: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return nil, fmt.Errorf("access denied")
		},
	}

	_, err := NewBrokerWithClient(context.Background(), mock)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGrantAccess(t *testing.T) {
	tests := []struct {
		name      string
		input     GrantAccessInput
		wantError bool
	}{
		{
			name: "valid single service read only",
			input: GrantAccessInput{
				Services: []string{"s3"},
				Level:    LevelReadOnly,
				TTL:      30 * time.Minute,
			},
		},
		{
			name: "valid multiple services full access",
			input: GrantAccessInput{
				Services: []string{"s3", "dynamodb"},
				Level:    LevelFull,
				TTL:      1 * time.Hour,
			},
		},
		{
			name: "ttl too short",
			input: GrantAccessInput{
				Services: []string{"s3"},
				Level:    LevelReadOnly,
				TTL:      5 * time.Minute,
			},
			wantError: true,
		},
		{
			name: "ttl too long",
			input: GrantAccessInput{
				Services: []string{"s3"},
				Level:    LevelReadOnly,
				TTL:      13 * time.Hour,
			},
			wantError: true,
		},
		{
			name: "unknown service",
			input: GrantAccessInput{
				Services: []string{"nonexistent"},
				Level:    LevelReadOnly,
				TTL:      30 * time.Minute,
			},
			wantError: true,
		},
		{
			name: "invalid level",
			input: GrantAccessInput{
				Services: []string{"s3"},
				Level:    "admin",
				TTL:      30 * time.Minute,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := defaultMock()
			broker := newTestBroker(t, mock)

			session, err := broker.GrantAccess(context.Background(), tt.input)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if session.ID == "" {
				t.Error("session ID should not be empty")
			}
			if session.AccessKeyID == "" {
				t.Error("AccessKeyID should not be empty")
			}
			if session.SecretAccessKey == "" {
				t.Error("SecretAccessKey should not be empty")
			}
			if session.SessionToken == "" {
				t.Error("SessionToken should not be empty")
			}
			if session.ExpiresAt.IsZero() {
				t.Error("ExpiresAt should not be zero")
			}
		})
	}
}

func TestGrantAccessSTSError(t *testing.T) {
	mock := defaultMock()
	mock.assumeRoleFn = func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
		return nil, fmt.Errorf("role not found")
	}

	broker := newTestBroker(t, mock)
	_, err := broker.GrantAccess(context.Background(), GrantAccessInput{
		Services: []string{"s3"},
		Level:    LevelReadOnly,
		TTL:      30 * time.Minute,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGrantAccessPolicyARNsPassedToSTS(t *testing.T) {
	mock := defaultMock()
	var capturedInput *sts.AssumeRoleInput
	mock.assumeRoleFn = func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
		capturedInput = params
		expiration := time.Now().Add(30 * time.Minute)
		return &sts.AssumeRoleOutput{
			Credentials: &ststypes.Credentials{
				AccessKeyId:     aws.String("AKIAIOSFODNN7EXAMPLE"),
				SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
				SessionToken:    aws.String("FwoGZXIvYXdzEBYaDH..."),
				Expiration:      aws.Time(expiration),
			},
		}, nil
	}

	broker := newTestBroker(t, mock)
	_, err := broker.GrantAccess(context.Background(), GrantAccessInput{
		Services: []string{"s3", "dynamodb"},
		Level:    LevelReadOnly,
		TTL:      30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedInput == nil {
		t.Fatal("AssumeRole was not called")
	}
	if len(capturedInput.PolicyArns) != 2 {
		t.Fatalf("expected 2 policy ARNs, got %d", len(capturedInput.PolicyArns))
	}
	if aws.ToInt32(capturedInput.DurationSeconds) != 1800 {
		t.Errorf("DurationSeconds = %d, want 1800", aws.ToInt32(capturedInput.DurationSeconds))
	}
}
