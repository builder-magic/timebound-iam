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

	"github.com/builder-magic/timebound-iam/cmd/cli"
	"github.com/builder-magic/timebound-iam/timebound/aws"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	serverName    = "timebound-iam"
	serverVersion = "0.5.0"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Printf("%s %s\n", serverName, serverVersion)
		os.Exit(0)
	case "help", "--help", "-h":
		printUsage()
		os.Exit(0)
	case "serve":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, "Start the MCP server on stdin/stdout")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "USAGE")
			fmt.Fprintln(os.Stderr, "  timebound-iam serve")
			os.Exit(0)
		}
		if err := runServe(); err != nil {
			log.Fatalf("serve: %v", err)
		}
	case "test":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, "Request test credentials and print verification instructions")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "USAGE")
			fmt.Fprintln(os.Stderr, "  timebound-iam test")
			os.Exit(0)
		}
		if err := runTest(); err != nil {
			log.Fatalf("test: %v", err)
		}
	case "setup":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, "Generate IAM trust and inline policies for the broker role")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "USAGE")
			fmt.Fprintln(os.Stderr, "  timebound-iam setup aws [--profile NAME]")
			os.Exit(0)
		}
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
	case "exec":
		if err := cli.RunExec(os.Args[2:]); err != nil {
			log.Fatalf("exec: %v", err)
		}
	case "env":
		if err := cli.RunEnv(os.Args[2:]); err != nil {
			log.Fatalf("env: %v", err)
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

func printUsage() {
	fmt.Fprintf(os.Stderr, "%s %s\n", serverName, serverVersion)
	fmt.Fprintln(os.Stderr, "Issue scoped, temporary AWS credentials via STS AssumeRole")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "USAGE")
	fmt.Fprintln(os.Stderr, "  timebound-iam <command> [flags]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "COMMANDS")
	fmt.Fprintln(os.Stderr, "  serve      Start the MCP server on stdin/stdout")
	fmt.Fprintln(os.Stderr, "  setup      Generate IAM policies for the broker role")
	fmt.Fprintln(os.Stderr, "  test       Request test credentials and verify the setup")
	fmt.Fprintln(os.Stderr, "  exec       Run a command with temporary credentials")
	fmt.Fprintln(os.Stderr, "  env        Print export/unset statements for shell use")
	fmt.Fprintln(os.Stderr, "  version    Print version information")
}

// hasHelpFlag reports whether args contains --help or -h.
func hasHelpFlag(args []string) bool {
	for _, a := range args {
		if a == "--help" || a == "-h" {
			return true
		}
	}
	return false
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
	fmt.Printf("  Secret Access Key: %s\n", timebound.Redact(session.SecretAccessKey, 4, 4))
	fmt.Printf("  Session Token:     %s\n", timebound.Redact(session.SessionToken, 20, 0))
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

