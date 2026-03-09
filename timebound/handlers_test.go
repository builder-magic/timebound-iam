package timebound

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/builder-magic/timebound-iam/timebound/core"
)

// mockProvider implements core.Provider for testing.
type mockProvider struct {
	name     string
	services []core.ServiceInfo
	grantFn  func(ctx context.Context, input core.GrantAccessInput) (*core.Session, error)
}

func (m *mockProvider) Name() string { return m.name }
func (m *mockProvider) ListServices() []core.ServiceInfo {
	return m.services
}
func (m *mockProvider) GrantAccess(ctx context.Context, input core.GrantAccessInput) (*core.Session, error) {
	return m.grantFn(ctx, input)
}

func defaultAWSMock() *mockProvider {
	return &mockProvider{
		name: core.ProviderAWS,
		services: []core.ServiceInfo{
			{Name: "s3", Levels: []string{core.LevelReadOnly, core.LevelFull}},
			{Name: "ec2", Levels: []string{core.LevelReadOnly, core.LevelFull}},
		},
		grantFn: func(ctx context.Context, input core.GrantAccessInput) (*core.Session, error) {
			return &core.Session{
				ID:       "test-aws-123",
				Provider: core.ProviderAWS,
				Services: input.Services,
				Level:    input.Level,
				Profile:  input.Profile,
				Credentials: map[string]string{
					"AWS_ACCESS_KEY_ID":     "AKIATEST",
					"AWS_SECRET_ACCESS_KEY": "SECRET",
					"AWS_SESSION_TOKEN":     "TOKEN",
				},
				ExpiresAt: time.Now().Add(30 * time.Minute),
			}, nil
		},
	}
}

func defaultAzureMock() *mockProvider {
	return &mockProvider{
		name: core.ProviderAzure,
		services: []core.ServiceInfo{
			{Name: "storage", Levels: []string{core.LevelReadOnly, core.LevelFull}},
			{Name: "keyvault", Levels: []string{core.LevelReadOnly, core.LevelFull}},
		},
		grantFn: func(ctx context.Context, input core.GrantAccessInput) (*core.Session, error) {
			return &core.Session{
				ID:       "test-azure-456",
				Provider: core.ProviderAzure,
				Services: input.Services,
				Level:    input.Level,
				Credentials: map[string]string{
					"AZURE_CLIENT_ID":       "client-id",
					"AZURE_CLIENT_SECRET":   "client-secret",
					"AZURE_TENANT_ID":       "tenant-id",
					"AZURE_SUBSCRIPTION_ID": "sub-id",
				},
				ExpiresAt: time.Now().Add(30 * time.Minute),
				Metadata: map[string]string{
					"role_assignment_ids": "uuid1,uuid2",
				},
			}, nil
		},
	}
}

func testProviders() map[string]core.Provider {
	return map[string]core.Provider{
		core.ProviderAWS:   defaultAWSMock(),
		core.ProviderAzure: defaultAzureMock(),
	}
}

func TestHandleGrantAccessAWS(t *testing.T) {
	providers := testProviders()
	store := core.NewSessionStore()

	result, _, err := handleGrantAccess(context.Background(), providers, store, t.TempDir(), grantAccessArgs{
		Services: []string{"s3"},
		Level:    core.LevelReadOnly,
		TTL:      "30m",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error result: %v", result.Content)
	}

	active := store.ListActive()
	if len(active) != 1 {
		t.Errorf("expected 1 active session, got %d", len(active))
	}
	if active[0].Provider != core.ProviderAWS {
		t.Errorf("expected AWS provider, got %q", active[0].Provider)
	}
}

func TestHandleGrantAccessAzure(t *testing.T) {
	providers := testProviders()
	store := core.NewSessionStore()

	result, _, err := handleGrantAccess(context.Background(), providers, store, t.TempDir(), grantAccessArgs{
		Provider: "azure",
		Services: []string{"storage"},
		Level:    core.LevelReadOnly,
		TTL:      "30m",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error result: %v", result.Content)
	}

	active := store.ListActive()
	if len(active) != 1 {
		t.Errorf("expected 1 active session, got %d", len(active))
	}
	if active[0].Provider != core.ProviderAzure {
		t.Errorf("expected Azure provider, got %q", active[0].Provider)
	}
}

func TestHandleGrantAccessUnknownProvider(t *testing.T) {
	providers := testProviders()
	store := core.NewSessionStore()

	result, _, err := handleGrantAccess(context.Background(), providers, store, t.TempDir(), grantAccessArgs{
		Provider: "gcp",
		Services: []string{"storage"},
		Level:    core.LevelReadOnly,
		TTL:      "30m",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for unknown provider")
	}
}

func TestHandleGrantAccessCredentialFile(t *testing.T) {
	providers := testProviders()
	store := core.NewSessionStore()
	credDir := t.TempDir()

	result, _, err := handleGrantAccess(context.Background(), providers, store, credDir, grantAccessArgs{
		Services: []string{"s3"},
		Level:    core.LevelReadOnly,
		TTL:      "30m",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text := extractText(result)
	var response map[string]any
	if err := json.Unmarshal([]byte(text), &response); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}

	credFile, ok := response["credential_file"].(string)
	if !ok || credFile == "" {
		t.Fatal("expected credential_file in response")
	}

	content, err := os.ReadFile(credFile)
	if err != nil {
		t.Fatalf("reading credential file: %v", err)
	}
	fileStr := string(content)
	if !strings.Contains(fileStr, "AWS_ACCESS_KEY_ID=AKIATEST") {
		t.Error("credential file missing access key")
	}
}

func TestHandleGrantAccessEmptyServices(t *testing.T) {
	providers := testProviders()
	store := core.NewSessionStore()

	result, _, err := handleGrantAccess(context.Background(), providers, store, t.TempDir(), grantAccessArgs{
		Services: []string{},
		Level:    core.LevelReadOnly,
		TTL:      "30m",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for empty services")
	}
}

func TestHandleGrantAccessInvalidLevel(t *testing.T) {
	providers := testProviders()
	store := core.NewSessionStore()

	result, _, err := handleGrantAccess(context.Background(), providers, store, t.TempDir(), grantAccessArgs{
		Services: []string{"s3"},
		Level:    "admin",
		TTL:      "30m",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for invalid level")
	}
}

func TestHandleListServicesDefaultProvider(t *testing.T) {
	providers := testProviders()

	result, _, err := handleListServices(providers, listServicesArgs{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatal("unexpected error result")
	}
}

func TestHandleListServicesAzure(t *testing.T) {
	providers := testProviders()

	result, _, err := handleListServices(providers, listServicesArgs{Provider: "azure"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatal("unexpected error result")
	}
}

func TestHandleListActiveSessions(t *testing.T) {
	store := core.NewSessionStore()

	store.Add(&core.Session{
		ID:        "aws-1",
		Provider:  core.ProviderAWS,
		Services:  []string{"s3"},
		Level:     core.LevelReadOnly,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	store.Add(&core.Session{
		ID:        "azure-1",
		Provider:  core.ProviderAzure,
		Services:  []string{"storage"},
		Level:     core.LevelFull,
		ExpiresAt: time.Now().Add(30 * time.Minute),
	})
	store.Add(&core.Session{
		ID:        "expired-1",
		Provider:  core.ProviderAWS,
		Services:  []string{"ec2"},
		Level:     core.LevelFull,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})

	result, _, err := handleListActiveSessions(store)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have 2 active sessions (1 AWS, 1 Azure).
	text := extractText(result)
	var sessions []map[string]any
	if err := json.Unmarshal([]byte(text), &sessions); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(sessions) != 2 {
		t.Errorf("expected 2 active sessions, got %d", len(sessions))
	}
}

func TestHandleListActiveSessionsEmpty(t *testing.T) {
	store := core.NewSessionStore()

	result, _, err := handleListActiveSessions(store)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text := extractText(result)
	var sessions []map[string]any
	if err := json.Unmarshal([]byte(text), &sessions); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}

// extractText gets the text content from an MCP CallToolResult.
func extractText(result interface{}) string {
	// Use type assertion chain to get text from MCP result.
	type textContent interface {
		GetText() string
	}
	// Fallback: marshal and inspect.
	b, err := json.Marshal(result)
	if err != nil {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return ""
	}
	content, ok := m["content"].([]any)
	if !ok || len(content) == 0 {
		return ""
	}
	first, ok := content[0].(map[string]any)
	if !ok {
		return ""
	}
	text, _ := first["text"].(string)
	return text
}
