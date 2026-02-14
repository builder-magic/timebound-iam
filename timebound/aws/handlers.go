package timebound

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	toolGrantAccess        = "grant_access"
	toolListServices       = "list_services"
	toolListActiveSessions = "list_active_sessions"
)

// grantAccessArgs holds the parsed arguments for the grant_access tool.
type grantAccessArgs struct {
	Services []string `json:"services" jsonschema:"AWS service names (e.g. s3 dynamodb lambda)"`
	Level    string   `json:"level" jsonschema:"Access level: read_only or full"`
	TTL      string   `json:"ttl" jsonschema:"Duration string (e.g. 15m 1h 4h)"`
	Profile  string   `json:"profile,omitempty" jsonschema:"Optional AWS profile name (e.g. prod dev). Omit for default credentials."`
}

// listServicesArgs holds the (empty) arguments for list_services.
type listServicesArgs struct{}

// listActiveSessionsArgs holds the (empty) arguments for list_active_sessions.
type listActiveSessionsArgs struct{}

// RegisterTools registers all MCP tool handlers on the server.
// credentialDir is the directory where credential .env files are written.
// The caller is responsible for creating this directory securely (e.g. via
// os.MkdirTemp) so that the path is unpredictable and not susceptible to
// symlink attacks.
func RegisterTools(server *mcp.Server, broker CredentialGranter, store *SessionStore, credentialDir string) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        toolGrantAccess,
		Description: "Issue time-boxed, service-scoped temporary AWS credentials. Optionally specify a profile to target a specific AWS account. The user will be prompted to approve before credentials are issued.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args grantAccessArgs) (*mcp.CallToolResult, any, error) {
		return handleGrantAccess(ctx, broker, store, credentialDir, args)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        toolListServices,
		Description: "List all AWS services available for temporary credential grants, along with their supported access levels.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args listServicesArgs) (*mcp.CallToolResult, any, error) {
		return handleListServices()
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        toolListActiveSessions,
		Description: "List all active (non-expired) temporary credential sessions.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args listActiveSessionsArgs) (*mcp.CallToolResult, any, error) {
		return handleListActiveSessions(store)
	})
}

func handleGrantAccess(ctx context.Context, broker CredentialGranter, store *SessionStore, credentialDir string, args grantAccessArgs) (*mcp.CallToolResult, any, error) {
	if len(args.Services) == 0 {
		return errorResult("at least one service is required"), nil, nil
	}

	if args.Level != LevelReadOnly && args.Level != LevelFull {
		return errorResult(fmt.Sprintf("invalid level %q: must be %s or %s", args.Level, LevelReadOnly, LevelFull)), nil, nil
	}

	ttl, err := time.ParseDuration(args.TTL)
	if err != nil {
		return errorResult(fmt.Sprintf("invalid TTL %q: %v", args.TTL, err)), nil, nil
	}

	session, err := broker.GrantAccess(ctx, GrantAccessInput{
		Services: args.Services,
		Level:    args.Level,
		TTL:      ttl,
		Profile:  args.Profile,
	})
	if err != nil {
		return errorResult(fmt.Sprintf("failed to grant access: %v", err)), nil, nil
	}

	// Write credentials to a temp file so they don't appear in tool output or command lines.
	// Write before adding to store so we don't have a session with no credential file.
	envFile, err := writeCredentialFile(credentialDir, session)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to write credential file: %v", err)), nil, nil
	}

	store.Add(session)

	// Clean up credential files for expired sessions
	cleanupExpiredCredentialFiles(credentialDir, store)

	response := map[string]any{
		"session_id":      session.ID,
		"services":        session.Services,
		"level":           session.Level,
		"expires_at":      session.ExpiresAt.Format(time.RFC3339),
		"credential_file": envFile,
		"usage":           fmt.Sprintf("Prefix AWS CLI commands with: env $(cat %s)", envFile),
	}

	if session.Profile != "" {
		response["profile"] = session.Profile
	}

	return jsonResult(response)
}

func handleListServices() (*mcp.CallToolResult, any, error) {
	services := ListServices()
	return jsonResult(services)
}

func handleListActiveSessions(store *SessionStore) (*mcp.CallToolResult, any, error) {
	sessions := store.ListActive()

	type sessionSummary struct {
		ID           string   `json:"id"`
		Services     []string `json:"services"`
		Level        string   `json:"level"`
		Profile      string   `json:"profile,omitempty"`
		ExpiresAt    string   `json:"expires_at"`
		TTLRemaining string   `json:"ttl_remaining"`
	}

	summaries := make([]sessionSummary, len(sessions))
	for i, s := range sessions {
		remaining := time.Until(s.ExpiresAt).Truncate(time.Second)
		summaries[i] = sessionSummary{
			ID:           s.ID,
			Services:     s.Services,
			Level:        s.Level,
			Profile:      s.Profile,
			ExpiresAt:    s.ExpiresAt.Format(time.RFC3339),
			TTLRemaining: remaining.String(),
		}
	}

	return jsonResult(summaries)
}

// StartCleanupLoop runs a background goroutine that periodically purges
// expired sessions and removes their credential files. It stops when
// ctx is cancelled.
func StartCleanupLoop(ctx context.Context, store *SessionStore, credentialDir string, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanupExpiredCredentialFiles(credentialDir, store)
			}
		}
	}()
}

// cleanupExpiredCredentialFiles removes credential files for expired sessions
// and purges them from the store.
func cleanupExpiredCredentialFiles(credentialDir string, store *SessionStore) {
	expired := store.PurgeExpired()
	for _, session := range expired {
		path := filepath.Join(credentialDir, session.ID+".env")
		os.Remove(path)
	}
}

// writeCredentialFile writes session credentials to a file in credentialDir
// and returns the path. The directory must already exist.
func writeCredentialFile(credentialDir string, session *Session) (string, error) {
	envFile := filepath.Join(credentialDir, session.ID+".env")
	content := strings.Join([]string{
		fmt.Sprintf("AWS_ACCESS_KEY_ID=%s", session.AccessKeyID),
		fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s", session.SecretAccessKey),
		fmt.Sprintf("AWS_SESSION_TOKEN=%s", session.SessionToken),
	}, "\n") + "\n"

	if err := os.WriteFile(envFile, []byte(content), 0600); err != nil {
		return "", fmt.Errorf("writing credential file: %w", err)
	}

	return envFile, nil
}

// jsonResult marshals data to JSON and returns it as a text content result.
func jsonResult(data any) (*mcp.CallToolResult, any, error) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling response: %w", err)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(b)},
		},
	}, nil, nil
}

// errorResult returns a tool result indicating an error to the caller.
func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{
			&mcp.TextContent{Text: msg},
		},
	}
}
