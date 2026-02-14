package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/deepmesa/timebound-iam/timebound/aws"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	serverName    = "timebound-iam"
	serverVersion = "0.1.0"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: timebound-iam <command>")
		fmt.Fprintln(os.Stderr, "commands: serve, setup, test")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		if err := runServe(); err != nil {
			log.Fatalf("serve: %v", err)
		}
	case "test":
		if err := runTest(); err != nil {
			log.Fatalf("test: %v", err)
		}
	case "setup":
		if len(os.Args) < 3 || os.Args[2] != "aws" {
			fmt.Fprintln(os.Stderr, "usage: timebound-iam setup aws [--profile NAME]")
			os.Exit(1)
		}
		setupFlags := flag.NewFlagSet("setup aws", flag.ExitOnError)
		profile := setupFlags.String("profile", "", "AWS profile name")
		setupFlags.Parse(os.Args[3:])
		if err := timebound.RunSetup(*profile); err != nil {
			log.Fatalf("setup: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func runServe() error {
	// Cancel the context on SIGINT or SIGTERM so that server.Run returns
	// and deferred cleanup (credential directory removal) executes.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Create a per-process credential directory with an unpredictable name.
	// This prevents symlink attacks against a hardcoded path in /tmp.
	credentialDir, err := os.MkdirTemp("", "timebound-iam-*")
	if err != nil {
		return fmt.Errorf("creating credential directory: %w", err)
	}
	defer os.RemoveAll(credentialDir)

	store := timebound.NewSessionStore()
	brokerPool := timebound.NewBrokerPool()

	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: serverVersion,
	}, nil)

	timebound.RegisterTools(server, brokerPool, store, credentialDir)
	timebound.StartCleanupLoop(ctx, store, credentialDir, 1*time.Minute)

	log.Printf("starting %s %s MCP server (brokers initialized on first use)", serverName, serverVersion)

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

func runTest() error {
	ctx := context.Background()

	fmt.Println("Initializing broker...")
	broker, err := timebound.NewBroker(ctx)
	if err != nil {
		return fmt.Errorf("broker init failed: %w", err)
	}
	fmt.Printf("Account:    %s\n", broker.AccountID())
	fmt.Printf("Broker ARN: %s\n\n", broker.BrokerRoleARN())

	fmt.Println("Requesting S3 read-only access for 15m...")
	session, err := broker.GrantAccess(ctx, timebound.GrantAccessInput{
		Services: []string{"s3"},
		Level:    timebound.LevelReadOnly,
		TTL:      15 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("grant_access failed: %w", err)
	}

	fmt.Println("Credentials received:")
	fmt.Printf("  Session ID:        %s\n", session.ID)
	fmt.Printf("  Access Key ID:     %s\n", session.AccessKeyID)
	fmt.Printf("  Secret Access Key: %s\n", redact(session.SecretAccessKey, 4, 4))
	fmt.Printf("  Session Token:     %s\n", redact(session.SessionToken, 20, 0))
	fmt.Printf("  Expires At:        %s\n\n", session.ExpiresAt.Format(time.RFC3339))

	// Write credentials to a file instead of printing them to the terminal.
	// Terminal scrollback, shell history, and log capture are all attack vectors.
	envFile := filepath.Join(os.TempDir(), fmt.Sprintf("timebound-iam-test-%s.env", session.ID))
	content := strings.Join([]string{
		fmt.Sprintf("AWS_ACCESS_KEY_ID=%s", session.AccessKeyID),
		fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s", session.SecretAccessKey),
		fmt.Sprintf("AWS_SESSION_TOKEN=%s", session.SessionToken),
	}, "\n") + "\n"
	if err := os.WriteFile(envFile, []byte(content), 0600); err != nil {
		return fmt.Errorf("writing credential file: %w", err)
	}

	fmt.Println("To verify, run:")
	fmt.Printf("  env $(cat %s) aws s3 ls\n", envFile)

	return nil
}

// redact returns a partially masked version of s, showing only the first
// prefixLen and last suffixLen characters. If s is too short to redact
// meaningfully, it is fully masked to avoid leaking the entire value.
// AWS credential values are ASCII so byte indexing is safe.
func redact(s string, prefixLen, suffixLen int) string {
	if len(s) == 0 {
		return ""
	}
	if prefixLen+suffixLen == 0 || len(s) <= prefixLen+suffixLen {
		return strings.Repeat("*", len(s))
	}
	if suffixLen == 0 {
		return s[:prefixLen] + "..."
	}
	return s[:prefixLen] + "..." + s[len(s)-suffixLen:]
}
