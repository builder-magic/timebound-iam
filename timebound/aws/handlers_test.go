package timebound

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestHandleGrantAccess(t *testing.T) {
	tests := []struct {
		name      string
		args      grantAccessArgs
		wantError bool
	}{
		{
			name: "valid request",
			args: grantAccessArgs{
				Services: []string{"s3"},
				Level:    LevelReadOnly,
				TTL:      "30m",
			},
		},
		{
			name: "multiple services",
			args: grantAccessArgs{
				Services: []string{"s3", "dynamodb"},
				Level:    LevelFull,
				TTL:      "1h",
			},
		},
		{
			name: "empty services",
			args: grantAccessArgs{
				Services: []string{},
				Level:    LevelReadOnly,
				TTL:      "30m",
			},
			wantError: true,
		},
		{
			name: "invalid level",
			args: grantAccessArgs{
				Services: []string{"s3"},
				Level:    "admin",
				TTL:      "30m",
			},
			wantError: true,
		},
		{
			name: "invalid ttl format",
			args: grantAccessArgs{
				Services: []string{"s3"},
				Level:    LevelReadOnly,
				TTL:      "not-a-duration",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := defaultMock()
			broker := newTestBroker(t, mock)
			store := NewSessionStore()

			result, _, err := handleGrantAccess(context.Background(), broker, store, tt.args)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantError {
				if !result.IsError {
					t.Fatal("expected error result")
				}
				return
			}
			if result.IsError {
				t.Fatalf("unexpected error result: %v", result.Content)
			}

			// Verify the session was stored
			active := store.ListActive()
			if len(active) != 1 {
				t.Errorf("expected 1 active session, got %d", len(active))
			}
		})
	}
}

func TestHandleGrantAccessResponse(t *testing.T) {
	expiration := time.Now().Add(30 * time.Minute)
	mock := &mockSTSClient{
		getCallerIdentityFn: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Account: aws.String("123456789012"),
			}, nil
		},
		assumeRoleFn: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			return &sts.AssumeRoleOutput{
				Credentials: &ststypes.Credentials{
					AccessKeyId:     aws.String("AKIATEST"),
					SecretAccessKey: aws.String("SECRET"),
					SessionToken:    aws.String("TOKEN"),
					Expiration:      aws.Time(expiration),
				},
			}, nil
		},
	}

	broker := newTestBroker(t, mock)
	store := NewSessionStore()

	result, _, err := handleGrantAccess(context.Background(), broker, store, grantAccessArgs{
		Services: []string{"s3"},
		Level:    LevelReadOnly,
		TTL:      "30m",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse the JSON response
	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("expected TextContent")
	}

	var response map[string]any
	if err := json.Unmarshal([]byte(textContent.Text), &response); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}

	// Credentials should NOT be in the response — they're written to a file
	if response["access_key_id"] != nil {
		t.Error("access_key_id should not be in response")
	}
	if response["secret_access_key"] != nil {
		t.Error("secret_access_key should not be in response")
	}
	if response["session_token"] != nil {
		t.Error("session_token should not be in response")
	}

	// credential_file should be present
	credFile, ok := response["credential_file"].(string)
	if !ok || credFile == "" {
		t.Fatal("expected credential_file in response")
	}

	// Verify the file exists and contains credentials
	content, err := os.ReadFile(credFile)
	if err != nil {
		t.Fatalf("reading credential file: %v", err)
	}
	fileStr := string(content)
	if !strings.Contains(fileStr, "AWS_ACCESS_KEY_ID=AKIATEST") {
		t.Error("credential file missing access key")
	}
	if !strings.Contains(fileStr, "AWS_SECRET_ACCESS_KEY=SECRET") {
		t.Error("credential file missing secret key")
	}
	if !strings.Contains(fileStr, "AWS_SESSION_TOKEN=TOKEN") {
		t.Error("credential file missing session token")
	}

	// Verify file permissions are 0600
	info, err := os.Stat(credFile)
	if err != nil {
		t.Fatalf("stat credential file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("file permissions = %o, want 0600", info.Mode().Perm())
	}

	// Clean up
	os.Remove(credFile)
}

func TestHandleListServices(t *testing.T) {
	result, _, err := handleListServices()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatal("unexpected error result")
	}

	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("expected TextContent")
	}

	var services []ServiceInfo
	if err := json.Unmarshal([]byte(textContent.Text), &services); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(services) == 0 {
		t.Fatal("expected at least one service")
	}
}

func TestHandleListActiveSessions(t *testing.T) {
	store := NewSessionStore()

	// Add some test sessions
	store.Add(&Session{
		ID:        "active-1",
		Services:  []string{"s3"},
		Level:     LevelReadOnly,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	store.Add(&Session{
		ID:        "expired-1",
		Services:  []string{"ec2"},
		Level:     LevelFull,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})

	result, _, err := handleListActiveSessions(store)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("expected TextContent")
	}

	var sessions []map[string]any
	if err := json.Unmarshal([]byte(textContent.Text), &sessions); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(sessions) != 1 {
		t.Errorf("expected 1 active session, got %d", len(sessions))
	}
	if sessions[0]["id"] != "active-1" {
		t.Errorf("expected session active-1, got %v", sessions[0]["id"])
	}
}

func TestHandleListActiveSessionsEmpty(t *testing.T) {
	store := NewSessionStore()

	result, _, err := handleListActiveSessions(store)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("expected TextContent")
	}

	var sessions []map[string]any
	if err := json.Unmarshal([]byte(textContent.Text), &sessions); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}
