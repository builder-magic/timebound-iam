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

const credentialDir = "/tmp/timebound-iam"

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
}

// listServicesArgs holds the (empty) arguments for list_services.
type listServicesArgs struct{}

// listActiveSessionsArgs holds the (empty) arguments for list_active_sessions.
type listActiveSessionsArgs struct{}

// RegisterTools registers all MCP tool handlers on the server.
func RegisterTools(server *mcp.Server, broker CredentialGranter, store *SessionStore) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        toolGrantAccess,
		Description: "Issue time-boxed, service-scoped temporary AWS credentials. The user will be prompted to approve before credentials are issued.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args grantAccessArgs) (*mcp.CallToolResult, any, error) {
		return handleGrantAccess(ctx, broker, store, args)
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

func handleGrantAccess(ctx context.Context, broker CredentialGranter, store *SessionStore, args grantAccessArgs) (*mcp.CallToolResult, any, error) {
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
	})
	if err != nil {
		return errorResult(fmt.Sprintf("failed to grant access: %v", err)), nil, nil
	}

	// Write credentials to a temp file so they don't appear in tool output or command lines.
	// Write before adding to store so we don't have a session with no credential file.
	envFile, err := writeCredentialFile(session)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to write credential file: %v", err)), nil, nil
	}

	store.Add(session)

	// Clean up credential files for expired sessions
	cleanupExpiredCredentialFiles(store)

	response := map[string]any{
		"session_id":      session.ID,
		"services":        session.Services,
		"level":           session.Level,
		"expires_at":      session.ExpiresAt.Format(time.RFC3339),
		"credential_file": envFile,
		"usage":           fmt.Sprintf("Prefix AWS CLI commands with: env $(cat %s)", envFile),
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
			ExpiresAt:    s.ExpiresAt.Format(time.RFC3339),
			TTLRemaining: remaining.String(),
		}
	}

	return jsonResult(summaries)
}

// cleanupExpiredCredentialFiles removes credential files for expired sessions
// and purges them from the store.
func cleanupExpiredCredentialFiles(store *SessionStore) {
	expired := store.PurgeExpired()
	for _, session := range expired {
		path := filepath.Join(credentialDir, session.ID+".env")
		os.Remove(path)
	}
}

// writeCredentialFile writes session credentials to a temp file and returns the path.
func writeCredentialFile(session *Session) (string, error) {
	if err := os.MkdirAll(credentialDir, 0700); err != nil {
		return "", fmt.Errorf("creating credential dir: %w", err)
	}

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
