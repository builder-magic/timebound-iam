package aws

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/builder-magic/timebound-iam/timebound/core"
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
		input     core.GrantAccessInput
		wantError bool
	}{
		{
			name: "valid single service read only",
			input: core.GrantAccessInput{
				Services: []string{"s3"},
				Level:    core.LevelReadOnly,
				TTL:      30 * time.Minute,
			},
		},
		{
			name: "valid multiple services full access",
			input: core.GrantAccessInput{
				Services: []string{"s3", "dynamodb"},
				Level:    core.LevelFull,
				TTL:      1 * time.Hour,
			},
		},
		{
			name: "ttl too short",
			input: core.GrantAccessInput{
				Services: []string{"s3"},
				Level:    core.LevelReadOnly,
				TTL:      5 * time.Minute,
			},
			wantError: true,
		},
		{
			name: "ttl too long",
			input: core.GrantAccessInput{
				Services: []string{"s3"},
				Level:    core.LevelReadOnly,
				TTL:      13 * time.Hour,
			},
			wantError: true,
		},
		{
			name: "unknown service",
			input: core.GrantAccessInput{
				Services: []string{"nonexistent"},
				Level:    core.LevelReadOnly,
				TTL:      30 * time.Minute,
			},
			wantError: true,
		},
		{
			name: "invalid level",
			input: core.GrantAccessInput{
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
			if session.Credentials[credKeyAccessKeyID] == "" {
				t.Error("AccessKeyID should not be empty")
			}
			if session.Credentials[credKeySecretAccessKey] == "" {
				t.Error("SecretAccessKey should not be empty")
			}
			if session.Credentials[credKeySessionToken] == "" {
				t.Error("SessionToken should not be empty")
			}
			if session.ExpiresAt.IsZero() {
				t.Error("ExpiresAt should not be zero")
			}
			if session.Provider != core.ProviderAWS {
				t.Errorf("Provider = %q, want %q", session.Provider, core.ProviderAWS)
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
	_, err := broker.GrantAccess(context.Background(), core.GrantAccessInput{
		Services: []string{"s3"},
		Level:    core.LevelReadOnly,
		TTL:      30 * time.Minute,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestBrokerPoolCaching(t *testing.T) {
	callCount := 0
	factory := func(ctx context.Context, profile string) (*Broker, error) {
		callCount++
		mock := defaultMock()
		return NewBrokerWithClient(ctx, mock)
	}

	pool := newBrokerPoolWithFactory(factory)
	ctx := context.Background()

	input := core.GrantAccessInput{
		Services: []string{"s3"},
		Level:    core.LevelReadOnly,
		TTL:      30 * time.Minute,
		Profile:  "dev",
	}

	// First call creates the broker
	if _, err := pool.GrantAccess(ctx, input); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("factory called %d times, want 1", callCount)
	}

	// Second call reuses the cached broker
	if _, err := pool.GrantAccess(ctx, input); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("factory called %d times after second call, want 1", callCount)
	}
}

func TestBrokerPoolMultiProfile(t *testing.T) {
	profiles := make(map[string]int)
	factory := func(ctx context.Context, profile string) (*Broker, error) {
		profiles[profile]++
		mock := defaultMock()
		return NewBrokerWithClient(ctx, mock)
	}

	pool := newBrokerPoolWithFactory(factory)
	ctx := context.Background()

	for _, profile := range []string{"dev", "prod", "dev"} {
		input := core.GrantAccessInput{
			Services: []string{"s3"},
			Level:    core.LevelReadOnly,
			TTL:      30 * time.Minute,
			Profile:  profile,
		}
		if _, err := pool.GrantAccess(ctx, input); err != nil {
			t.Fatalf("profile %q: %v", profile, err)
		}
	}

	if profiles["dev"] != 1 {
		t.Errorf("dev factory calls = %d, want 1", profiles["dev"])
	}
	if profiles["prod"] != 1 {
		t.Errorf("prod factory calls = %d, want 1", profiles["prod"])
	}
}

func TestBrokerPoolInitError(t *testing.T) {
	callCount := 0
	factory := func(ctx context.Context, profile string) (*Broker, error) {
		callCount++
		return nil, fmt.Errorf("credential error")
	}

	pool := newBrokerPoolWithFactory(factory)
	ctx := context.Background()
	input := core.GrantAccessInput{
		Services: []string{"s3"},
		Level:    core.LevelReadOnly,
		TTL:      30 * time.Minute,
		Profile:  "broken",
	}

	// First call fails
	if _, err := pool.GrantAccess(ctx, input); err == nil {
		t.Fatal("expected error, got nil")
	}
	if callCount != 1 {
		t.Fatalf("factory called %d times, want 1", callCount)
	}

	// Second call retries — failed init should not be cached
	if _, err := pool.GrantAccess(ctx, input); err == nil {
		t.Fatal("expected error on retry, got nil")
	}
	if callCount != 2 {
		t.Fatalf("factory called %d times after retry, want 2", callCount)
	}
}

func TestBrokerPoolDefaultProfile(t *testing.T) {
	factory := func(ctx context.Context, profile string) (*Broker, error) {
		if profile != "" {
			t.Errorf("expected empty profile, got %q", profile)
		}
		mock := defaultMock()
		return NewBrokerWithClient(ctx, mock)
	}

	pool := newBrokerPoolWithFactory(factory)
	ctx := context.Background()
	input := core.GrantAccessInput{
		Services: []string{"s3"},
		Level:    core.LevelReadOnly,
		TTL:      30 * time.Minute,
	}

	if _, err := pool.GrantAccess(ctx, input); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Concurrency tests: run with -race to detect data races.

func TestBrokerPoolConcurrentSameProfile(t *testing.T) {
	var factoryCalls atomic.Int32
	factory := func(ctx context.Context, profile string) (*Broker, error) {
		factoryCalls.Add(1)
		mock := defaultMock()
		return NewBrokerWithClient(ctx, mock)
	}

	pool := newBrokerPoolWithFactory(factory)
	ctx := context.Background()

	const goroutines = 20
	brokers := make([]*Broker, goroutines)
	errs := make([]error, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			b, err := pool.getOrCreate(ctx, "shared")
			brokers[idx] = b
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: unexpected error: %v", i, err)
		}
	}

	// All goroutines must receive the same broker instance.
	for i := 1; i < goroutines; i++ {
		if brokers[i] != brokers[0] {
			t.Fatalf("goroutine %d got a different broker instance", i)
		}
	}

	if n := factoryCalls.Load(); n != 1 {
		t.Errorf("factory called %d times, want 1", n)
	}
}

func TestBrokerPoolDifferentProfilesNotBlocked(t *testing.T) {
	// Factory that blocks until released via a per-profile gate channel.
	gates := map[string]chan struct{}{
		"a": make(chan struct{}),
		"b": make(chan struct{}),
	}

	factory := func(ctx context.Context, profile string) (*Broker, error) {
		gate, ok := gates[profile]
		if !ok {
			return nil, fmt.Errorf("unexpected profile %q", profile)
		}
		<-gate
		mock := defaultMock()
		return NewBrokerWithClient(ctx, mock)
	}

	pool := newBrokerPoolWithFactory(factory)
	ctx := context.Background()

	// Start profile A. It will block inside the factory.
	aReady := make(chan struct{})
	aDone := make(chan struct{})
	go func() {
		close(aReady)
		pool.getOrCreate(ctx, "a")
		close(aDone)
	}()
	<-aReady
	time.Sleep(10 * time.Millisecond)

	// Release profile B's gate and request it.
	close(gates["b"])
	bDone := make(chan struct{})
	go func() {
		pool.getOrCreate(ctx, "b")
		close(bDone)
	}()

	select {
	case <-bDone:
	case <-time.After(2 * time.Second):
		t.Fatal("profile B blocked by profile A's pending creation")
	}

	// Verify A is still blocked.
	select {
	case <-aDone:
		t.Fatal("profile A completed before its gate was released")
	default:
	}

	// Release A and wait for it to finish.
	close(gates["a"])
	select {
	case <-aDone:
	case <-time.After(2 * time.Second):
		t.Fatal("profile A did not complete after gate was released")
	}
}

func TestBrokerPoolConcurrentFactoryErrorRetryable(t *testing.T) {
	var factoryCalls atomic.Int32
	factory := func(ctx context.Context, profile string) (*Broker, error) {
		n := factoryCalls.Add(1)
		if n == 1 {
			return nil, fmt.Errorf("transient network error")
		}
		mock := defaultMock()
		return NewBrokerWithClient(ctx, mock)
	}

	pool := newBrokerPoolWithFactory(factory)
	ctx := context.Background()

	// First call fails.
	_, err := pool.getOrCreate(ctx, "flaky")
	if err == nil {
		t.Fatal("expected error on first call")
	}

	// Second call retries and succeeds.
	broker, err := pool.getOrCreate(ctx, "flaky")
	if err != nil {
		t.Fatalf("expected success on retry, got: %v", err)
	}
	if broker == nil {
		t.Fatal("expected non-nil broker on retry")
	}

	// Third call returns the cached broker.
	broker2, err := pool.getOrCreate(ctx, "flaky")
	if err != nil {
		t.Fatalf("third call: %v", err)
	}
	if broker2 != broker {
		t.Fatal("third call returned a different broker instance")
	}
	if n := factoryCalls.Load(); n != 2 {
		t.Errorf("factory called %d times, want 2", n)
	}
}

func TestGrantAccessWithServiceScopes(t *testing.T) {
	tests := []struct {
		name         string
		scopes       []core.ServiceScope
		wantARNCount int
		wantError    bool
		wantErrorMsg string
	}{
		{
			name: "mixed levels",
			scopes: []core.ServiceScope{
				{Service: "s3", Level: core.LevelReadOnly},
				{Service: "dynamodb", Level: core.LevelFull},
			},
			wantARNCount: 2,
		},
		{
			name: "deduplication same service same level",
			scopes: []core.ServiceScope{
				{Service: "s3", Level: core.LevelReadOnly},
				{Service: "s3", Level: core.LevelReadOnly},
			},
			wantARNCount: 1,
		},
		{
			name: "same service different levels produces two ARNs",
			scopes: []core.ServiceScope{
				{Service: "s3", Level: core.LevelReadOnly},
				{Service: "s3", Level: core.LevelFull},
			},
			wantARNCount: 2,
		},
		{
			name: "unknown service with scopes",
			scopes: []core.ServiceScope{
				{Service: "nonexistent", Level: core.LevelReadOnly},
			},
			wantError:    true,
			wantErrorMsg: "unknown service",
		},
		{
			name: "invalid level with scopes",
			scopes: []core.ServiceScope{
				{Service: "s3", Level: "admin"},
			},
			wantError:    true,
			wantErrorMsg: "invalid access level",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			_, err := broker.GrantAccess(context.Background(), core.GrantAccessInput{
				ServiceScopes: tt.scopes,
				TTL:           30 * time.Minute,
			})

			if tt.wantError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.wantErrorMsg != "" && !strings.Contains(err.Error(), tt.wantErrorMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrorMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if capturedInput == nil {
				t.Fatal("AssumeRole was not called")
			}
			if len(capturedInput.PolicyArns) != tt.wantARNCount {
				t.Errorf("expected %d policy ARNs, got %d", tt.wantARNCount, len(capturedInput.PolicyArns))
			}
		})
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
	_, err := broker.GrantAccess(context.Background(), core.GrantAccessInput{
		Services: []string{"s3", "dynamodb"},
		Level:    core.LevelReadOnly,
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
