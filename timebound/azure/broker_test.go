package azure

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/builder-magic/timebound-iam/timebound/core"
)

type mockRoleAssignmentsClient struct {
	createFn func(ctx context.Context, scope string, name string, params armauthorization.RoleAssignmentCreateParameters, opts *armauthorization.RoleAssignmentsClientCreateOptions) (armauthorization.RoleAssignmentsClientCreateResponse, error)
	deleteFn func(ctx context.Context, scope string, name string, opts *armauthorization.RoleAssignmentsClientDeleteOptions) (armauthorization.RoleAssignmentsClientDeleteResponse, error)
}

func (m *mockRoleAssignmentsClient) Create(ctx context.Context, scope string, name string, params armauthorization.RoleAssignmentCreateParameters, opts *armauthorization.RoleAssignmentsClientCreateOptions) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
	return m.createFn(ctx, scope, name, params, opts)
}

func (m *mockRoleAssignmentsClient) Delete(ctx context.Context, scope string, name string, opts *armauthorization.RoleAssignmentsClientDeleteOptions) (armauthorization.RoleAssignmentsClientDeleteResponse, error) {
	return m.deleteFn(ctx, scope, name, opts)
}

func testConfig() *Config {
	return &Config{
		TenantID:            "tenant-123",
		SubscriptionID:      "sub-456",
		ManagerClientID:     "mgr-client-789",
		ManagerClientSecret: "mgr-secret-abc",
		WorkerClientID:      "worker-client-789",
		WorkerClientSecret:  "worker-secret-abc",
		WorkerObjectID:      "worker-object-def",
	}
}

func defaultAzureMock() *mockRoleAssignmentsClient {
	return &mockRoleAssignmentsClient{
		createFn: func(ctx context.Context, scope string, name string, params armauthorization.RoleAssignmentCreateParameters, opts *armauthorization.RoleAssignmentsClientCreateOptions) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
			return armauthorization.RoleAssignmentsClientCreateResponse{}, nil
		},
		deleteFn: func(ctx context.Context, scope string, name string, opts *armauthorization.RoleAssignmentsClientDeleteOptions) (armauthorization.RoleAssignmentsClientDeleteResponse, error) {
			return armauthorization.RoleAssignmentsClientDeleteResponse{}, nil
		},
	}
}

func TestGrantAccess(t *testing.T) {
	// Fix time for deterministic tests.
	now := time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC)
	timeNow = func() time.Time { return now }
	defer func() { timeNow = time.Now }()

	mock := defaultAzureMock()
	broker := NewBrokerWithClient(testConfig(), mock)

	session, err := broker.GrantAccess(context.Background(), core.GrantAccessInput{
		Services: []string{"storage"},
		Level:    core.LevelReadOnly,
		TTL:      30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if session.Provider != core.ProviderAzure {
		t.Errorf("Provider = %q, want %q", session.Provider, core.ProviderAzure)
	}
	if session.ID == "" {
		t.Error("session ID should not be empty")
	}
	if session.Credentials["AZURE_CLIENT_ID"] != "worker-client-789" {
		t.Errorf("ClientID = %q, want %q", session.Credentials["AZURE_CLIENT_ID"], "worker-client-789")
	}
	if session.Credentials["AZURE_TENANT_ID"] != "tenant-123" {
		t.Errorf("TenantID = %q, want %q", session.Credentials["AZURE_TENANT_ID"], "tenant-123")
	}
	if session.Credentials["AZURE_SUBSCRIPTION_ID"] != "sub-456" {
		t.Errorf("SubscriptionID = %q, want %q", session.Credentials["AZURE_SUBSCRIPTION_ID"], "sub-456")
	}

	wantExpiry := now.Add(30 * time.Minute)
	if !session.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("ExpiresAt = %v, want %v", session.ExpiresAt, wantExpiry)
	}

	// Metadata should contain role assignment IDs.
	ids, ok := session.Metadata["role_assignment_ids"]
	if !ok || ids == "" {
		t.Error("expected role_assignment_ids in metadata")
	}
}

func TestGrantAccessMultipleServices(t *testing.T) {
	var createCalls int
	mock := defaultAzureMock()
	mock.createFn = func(ctx context.Context, scope string, name string, params armauthorization.RoleAssignmentCreateParameters, opts *armauthorization.RoleAssignmentsClientCreateOptions) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
		createCalls++
		return armauthorization.RoleAssignmentsClientCreateResponse{}, nil
	}

	broker := NewBrokerWithClient(testConfig(), mock)
	_, err := broker.GrantAccess(context.Background(), core.GrantAccessInput{
		Services: []string{"storage", "keyvault"},
		Level:    core.LevelFull,
		TTL:      1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// storage = 2 roles (Reader + Blob Data Contributor), keyvault = 1 role
	if createCalls != 3 {
		t.Errorf("expected 3 Create calls, got %d", createCalls)
	}
}

func TestGrantAccessTTLValidation(t *testing.T) {
	mock := defaultAzureMock()
	broker := NewBrokerWithClient(testConfig(), mock)

	tests := []struct {
		name string
		ttl  time.Duration
	}{
		{"too short", 5 * time.Minute},
		{"too long", 13 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := broker.GrantAccess(context.Background(), core.GrantAccessInput{
				Services: []string{"storage"},
				Level:    core.LevelReadOnly,
				TTL:      tt.ttl,
			})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestGrantAccessUnknownService(t *testing.T) {
	mock := defaultAzureMock()
	broker := NewBrokerWithClient(testConfig(), mock)

	_, err := broker.GrantAccess(context.Background(), core.GrantAccessInput{
		Services: []string{"nonexistent"},
		Level:    core.LevelReadOnly,
		TTL:      30 * time.Minute,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGrantAccessCreateError(t *testing.T) {
	mock := defaultAzureMock()
	mock.createFn = func(ctx context.Context, scope string, name string, params armauthorization.RoleAssignmentCreateParameters, opts *armauthorization.RoleAssignmentsClientCreateOptions) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
		return armauthorization.RoleAssignmentsClientCreateResponse{}, fmt.Errorf("permission denied")
	}

	broker := NewBrokerWithClient(testConfig(), mock)
	_, err := broker.GrantAccess(context.Background(), core.GrantAccessInput{
		Services: []string{"storage"},
		Level:    core.LevelReadOnly,
		TTL:      30 * time.Minute,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGrantAccessPartialCreateRollback(t *testing.T) {
	var deleteNames []string
	callCount := 0
	mock := &mockRoleAssignmentsClient{
		createFn: func(ctx context.Context, scope string, name string, params armauthorization.RoleAssignmentCreateParameters, opts *armauthorization.RoleAssignmentsClientCreateOptions) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
			callCount++
			if callCount == 2 {
				return armauthorization.RoleAssignmentsClientCreateResponse{}, fmt.Errorf("failed on second")
			}
			return armauthorization.RoleAssignmentsClientCreateResponse{}, nil
		},
		deleteFn: func(ctx context.Context, scope string, name string, opts *armauthorization.RoleAssignmentsClientDeleteOptions) (armauthorization.RoleAssignmentsClientDeleteResponse, error) {
			deleteNames = append(deleteNames, name)
			return armauthorization.RoleAssignmentsClientDeleteResponse{}, nil
		},
	}

	broker := NewBrokerWithClient(testConfig(), mock)
	_, err := broker.GrantAccess(context.Background(), core.GrantAccessInput{
		Services: []string{"storage", "keyvault"},
		Level:    core.LevelFull,
		TTL:      30 * time.Minute,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// The first successful assignment should have been cleaned up.
	if len(deleteNames) != 1 {
		t.Errorf("expected 1 rollback delete, got %d", len(deleteNames))
	}
}

func TestCleanup(t *testing.T) {
	var deletedNames []string
	mock := &mockRoleAssignmentsClient{
		createFn: func(ctx context.Context, scope string, name string, params armauthorization.RoleAssignmentCreateParameters, opts *armauthorization.RoleAssignmentsClientCreateOptions) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
			return armauthorization.RoleAssignmentsClientCreateResponse{}, nil
		},
		deleteFn: func(ctx context.Context, scope string, name string, opts *armauthorization.RoleAssignmentsClientDeleteOptions) (armauthorization.RoleAssignmentsClientDeleteResponse, error) {
			deletedNames = append(deletedNames, name)
			return armauthorization.RoleAssignmentsClientDeleteResponse{}, nil
		},
	}

	broker := NewBrokerWithClient(testConfig(), mock)

	session := &core.Session{
		ID:       "test-cleanup",
		Provider: core.ProviderAzure,
		Metadata: map[string]string{
			"role_assignment_ids": "uuid-1,uuid-2,uuid-3",
		},
	}

	err := broker.Cleanup(context.Background(), session)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deletedNames) != 3 {
		t.Errorf("expected 3 deletes, got %d", len(deletedNames))
	}
}

func TestCleanupNoMetadata(t *testing.T) {
	mock := defaultAzureMock()
	broker := NewBrokerWithClient(testConfig(), mock)

	session := &core.Session{
		ID:       "test-no-meta",
		Provider: core.ProviderAzure,
	}

	err := broker.Cleanup(context.Background(), session)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListServices(t *testing.T) {
	services := ListServices()
	if len(services) == 0 {
		t.Fatal("expected at least one service")
	}

	// Verify sorted order.
	for i := 1; i < len(services); i++ {
		if services[i].Name <= services[i-1].Name {
			t.Errorf("services not sorted: %s comes after %s", services[i].Name, services[i-1].Name)
		}
	}
}

func TestValidateServices(t *testing.T) {
	tests := []struct {
		name      string
		services  []string
		wantError bool
	}{
		{"valid", []string{"storage", "keyvault"}, false},
		{"unknown", []string{"storage", "bogus"}, true},
		{"empty", []string{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateServices(tt.services)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateServices() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestRoleAssignmentScope(t *testing.T) {
	var capturedScope string
	mock := &mockRoleAssignmentsClient{
		createFn: func(ctx context.Context, scope string, name string, params armauthorization.RoleAssignmentCreateParameters, opts *armauthorization.RoleAssignmentsClientCreateOptions) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
			capturedScope = scope
			return armauthorization.RoleAssignmentsClientCreateResponse{}, nil
		},
		deleteFn: func(ctx context.Context, scope string, name string, opts *armauthorization.RoleAssignmentsClientDeleteOptions) (armauthorization.RoleAssignmentsClientDeleteResponse, error) {
			return armauthorization.RoleAssignmentsClientDeleteResponse{}, nil
		},
	}

	broker := NewBrokerWithClient(testConfig(), mock)
	_, err := broker.GrantAccess(context.Background(), core.GrantAccessInput{
		Services: []string{"storage"},
		Level:    core.LevelReadOnly,
		TTL:      30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantScope := "/subscriptions/sub-456"
	if capturedScope != wantScope {
		t.Errorf("scope = %q, want %q", capturedScope, wantScope)
	}
}

func TestRoleDefinitionIDInCreateParams(t *testing.T) {
	var capturedRoleDefID string
	mock := &mockRoleAssignmentsClient{
		createFn: func(ctx context.Context, scope string, name string, params armauthorization.RoleAssignmentCreateParameters, opts *armauthorization.RoleAssignmentsClientCreateOptions) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
			if params.Properties != nil && params.Properties.RoleDefinitionID != nil {
				capturedRoleDefID = *params.Properties.RoleDefinitionID
			}
			return armauthorization.RoleAssignmentsClientCreateResponse{}, nil
		},
		deleteFn: func(ctx context.Context, scope string, name string, opts *armauthorization.RoleAssignmentsClientDeleteOptions) (armauthorization.RoleAssignmentsClientDeleteResponse, error) {
			return armauthorization.RoleAssignmentsClientDeleteResponse{}, nil
		},
	}

	broker := NewBrokerWithClient(testConfig(), mock)
	_, err := broker.GrantAccess(context.Background(), core.GrantAccessInput{
		Services: []string{"storage"},
		Level:    core.LevelReadOnly,
		TTL:      30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Storage Blob Data Reader role ID.
	wantRoleID := "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
	if !strings.Contains(capturedRoleDefID, wantRoleID) {
		t.Errorf("role definition ID %q does not contain %q", capturedRoleDefID, wantRoleID)
	}
}
