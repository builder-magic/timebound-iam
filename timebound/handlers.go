package timebound

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/builder-magic/timebound-iam/timebound/core"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	toolGrantAccess        = "grant_access"
	toolListServices       = "list_services"
	toolListActiveSessions = "list_active_sessions"
)

// grantAccessArgs holds the parsed arguments for the grant_access tool.
type grantAccessArgs struct {
	Provider string   `json:"provider,omitempty" jsonschema:"Cloud provider: aws or azure (default: aws)"`
	Services []string `json:"services" jsonschema:"Service names (e.g. s3 dynamodb for AWS; storage keyvault for Azure)"`
	Level    string   `json:"level" jsonschema:"Access level: read_only or full"`
	TTL      string   `json:"ttl" jsonschema:"Duration string (e.g. 15m 1h 4h)"`
	Profile  string   `json:"profile,omitempty" jsonschema:"Optional profile name (e.g. prod dev). Omit for default credentials."`
}

// listServicesArgs holds the arguments for list_services.
type listServicesArgs struct {
	Provider string `json:"provider,omitempty" jsonschema:"Cloud provider: aws or azure (default: aws)"`
}

// listActiveSessionsArgs holds the (empty) arguments for list_active_sessions.
type listActiveSessionsArgs struct{}

// RegisterTools registers all MCP tool handlers on the server.
func RegisterTools(server *mcp.Server, providers map[string]core.Provider, store *core.SessionStore, credentialDir string) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        toolGrantAccess,
		Description: "Issue time-boxed, service-scoped temporary cloud credentials. Supports AWS and Azure. Optionally specify a profile to target a specific account. The user will be prompted to approve before credentials are issued.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args grantAccessArgs) (*mcp.CallToolResult, any, error) {
		return handleGrantAccess(ctx, providers, store, credentialDir, args)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        toolListServices,
		Description: "List all cloud services available for temporary credential grants, along with their supported access levels. Supports AWS and Azure.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args listServicesArgs) (*mcp.CallToolResult, any, error) {
		return handleListServices(providers, args)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        toolListActiveSessions,
		Description: "List all active (non-expired) temporary credential sessions across all providers.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args listActiveSessionsArgs) (*mcp.CallToolResult, any, error) {
		return handleListActiveSessions(store)
	})
}

func handleGrantAccess(ctx context.Context, providers map[string]core.Provider, store *core.SessionStore, credentialDir string, args grantAccessArgs) (*mcp.CallToolResult, any, error) {
	providerName := args.Provider
	if providerName == "" {
		providerName = core.ProviderAWS
	}

	provider, ok := providers[providerName]
	if !ok {
		available := make([]string, 0, len(providers))
		for k := range providers {
			available = append(available, k)
		}
		return errorResult(fmt.Sprintf("unknown provider %q: available providers are %s", providerName, strings.Join(available, ", "))), nil, nil
	}

	if len(args.Services) == 0 {
		return errorResult("at least one service is required"), nil, nil
	}

	if args.Level != core.LevelReadOnly && args.Level != core.LevelFull {
		return errorResult(fmt.Sprintf("invalid level %q: must be %s or %s", args.Level, core.LevelReadOnly, core.LevelFull)), nil, nil
	}

	ttl, err := time.ParseDuration(args.TTL)
	if err != nil {
		return errorResult(fmt.Sprintf("invalid TTL %q: %v", args.TTL, err)), nil, nil
	}

	session, err := provider.GrantAccess(ctx, core.GrantAccessInput{
		Services: args.Services,
		Level:    args.Level,
		TTL:      ttl,
		Profile:  args.Profile,
	})
	if err != nil {
		return errorResult(fmt.Sprintf("failed to grant access: %v", err)), nil, nil
	}

	envFile, err := writeCredentialFile(credentialDir, session)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to write credential file: %v", err)), nil, nil
	}

	store.Add(session)
	cleanupExpiredCredentialFiles(credentialDir, store)

	response := map[string]any{
		"session_id":      session.ID,
		"provider":        session.Provider,
		"services":        session.Services,
		"level":           session.Level,
		"expires_at":      session.ExpiresAt.Format(time.RFC3339),
		"credential_file": envFile,
		"usage":           fmt.Sprintf("Prefix CLI commands with: env $(cat %s)", envFile),
	}

	if session.Profile != "" {
		response["profile"] = session.Profile
	}

	return jsonResult(response)
}

func handleListServices(providers map[string]core.Provider, args listServicesArgs) (*mcp.CallToolResult, any, error) {
	providerName := args.Provider
	if providerName == "" {
		providerName = core.ProviderAWS
	}

	provider, ok := providers[providerName]
	if !ok {
		available := make([]string, 0, len(providers))
		for k := range providers {
			available = append(available, k)
		}
		return errorResult(fmt.Sprintf("unknown provider %q: available providers are %s", providerName, strings.Join(available, ", "))), nil, nil
	}

	services := provider.ListServices()
	return jsonResult(services)
}

func handleListActiveSessions(store *core.SessionStore) (*mcp.CallToolResult, any, error) {
	sessions := store.ListActive()

	type sessionSummary struct {
		ID           string   `json:"id"`
		Provider     string   `json:"provider"`
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
			Provider:     s.Provider,
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
// ctx is cancelled. For Azure sessions, it also removes RBAC role assignments
// via the provided cleaners.
func StartCleanupLoop(ctx context.Context, store *core.SessionStore, credentialDir string, cleaners map[string]core.SessionCleaner, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanupExpired(ctx, credentialDir, store, cleaners)
			}
		}
	}()
}

// cleanupExpired removes credential files and runs provider-specific cleanup.
func cleanupExpired(ctx context.Context, credentialDir string, store *core.SessionStore, cleaners map[string]core.SessionCleaner) {
	expired := store.PurgeExpired()
	for _, session := range expired {
		path := filepath.Join(credentialDir, session.ID+".env")
		os.Remove(path)

		if cleaner, ok := cleaners[session.Provider]; ok {
			// Best effort cleanup; log errors but don't fail.
			if err := cleaner.Cleanup(ctx, session); err != nil {
				fmt.Fprintf(os.Stderr, "cleanup error for session %s (%s): %v\n", session.ID, session.Provider, err)
			}
		}
	}
}

// cleanupExpiredCredentialFiles removes credential files for expired sessions.
func cleanupExpiredCredentialFiles(credentialDir string, store *core.SessionStore) {
	expired := store.PurgeExpired()
	for _, session := range expired {
		path := filepath.Join(credentialDir, session.ID+".env")
		os.Remove(path)
	}
}

// writeCredentialFile writes session credentials to a file and returns the path.
func writeCredentialFile(credentialDir string, session *core.Session) (string, error) {
	envFile := filepath.Join(credentialDir, session.ID+".env")

	lines := make([]string, 0, len(session.Credentials))
	for k, v := range session.Credentials {
		lines = append(lines, fmt.Sprintf("%s=%s", k, v))
	}
	// Sort for deterministic output.
	sortedLines := make([]string, len(lines))
	copy(sortedLines, lines)
	sortStrings(sortedLines)
	content := strings.Join(sortedLines, "\n") + "\n"

	if err := os.WriteFile(envFile, []byte(content), 0600); err != nil {
		return "", fmt.Errorf("writing credential file: %w", err)
	}

	return envFile, nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
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
