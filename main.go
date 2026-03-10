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
	"github.com/builder-magic/timebound-iam/timebound"
	awsprovider "github.com/builder-magic/timebound-iam/timebound/aws"
	azureprovider "github.com/builder-magic/timebound-iam/timebound/azure"
	"github.com/builder-magic/timebound-iam/timebound/core"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	serverName    = "timebound-iam"
	serverVersion = "0.8.2"

	defaultDirName   = ".tiam"
	credentialSubdir = "creds"
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
			fmt.Fprintln(os.Stderr, "  timebound-iam test [aws|azure]")
			os.Exit(0)
		}
		provider := "aws"
		if len(os.Args) > 2 && (os.Args[2] == "aws" || os.Args[2] == "azure") {
			provider = os.Args[2]
		}
		switch provider {
		case "azure":
			if err := runTestAzure(); err != nil {
				log.Fatalf("test azure: %v", err)
			}
		default:
			if err := runTest(); err != nil {
				log.Fatalf("test: %v", err)
			}
		}
	case "setup":
		if hasHelpFlag(os.Args[2:]) {
			fmt.Fprintln(os.Stderr, "Set up cloud provider credentials for the broker")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "USAGE")
			fmt.Fprintln(os.Stderr, "  timebound-iam setup aws [--profile NAME]")
			fmt.Fprintln(os.Stderr, "  timebound-iam setup azure")
			os.Exit(0)
		}
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: timebound-iam setup <aws|azure> [flags]")
			os.Exit(1)
		}
		switch os.Args[2] {
		case "aws":
			setupFlags := flag.NewFlagSet("setup aws", flag.ExitOnError)
			profile := setupFlags.String("profile", "", "AWS profile name")
			setupFlags.Parse(os.Args[3:])
			if err := awsprovider.RunSetup(*profile); err != nil {
				log.Fatalf("setup: %v", err)
			}
		case "azure":
			if err := azureprovider.RunSetup(); err != nil {
				log.Fatalf("setup: %v", err)
			}
		default:
			fmt.Fprintf(os.Stderr, "unknown provider: %s (use aws or azure)\n", os.Args[2])
			os.Exit(1)
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	credentialDir, err := resolveCredentialDir()
	if err != nil {
		return fmt.Errorf("setting up credential directory: %w", err)
	}

	store := core.NewSessionStore()

	// Register available providers. AWS is always available (uses default
	// credential chain). Azure is available only if configured.
	providers := make(map[string]core.Provider)
	cleaners := make(map[string]core.SessionCleaner)

	awsPool := awsprovider.NewBrokerPool()
	providers[core.ProviderAWS] = awsPool

	azureBroker, err := azureprovider.NewBroker(ctx)
	if err != nil {
		log.Printf("Azure provider not available: %v", err)
	} else {
		providers[core.ProviderAzure] = azureBroker
		cleaners[core.ProviderAzure] = azureBroker
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: serverVersion,
	}, nil)

	timebound.RegisterTools(server, providers, store, credentialDir)
	timebound.StartCleanupLoop(ctx, store, credentialDir, cleaners, 1*time.Minute)

	log.Printf("starting %s %s MCP server (credentials in %s)", serverName, serverVersion, credentialDir)

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "%s %s\n", serverName, serverVersion)
	fmt.Fprintln(os.Stderr, "Issue scoped, temporary cloud credentials (AWS and Azure)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "USAGE")
	fmt.Fprintln(os.Stderr, "  timebound-iam <command> [flags]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "COMMANDS")
	fmt.Fprintln(os.Stderr, "  serve      Start the MCP server on stdin/stdout")
	fmt.Fprintln(os.Stderr, "  setup      Set up cloud provider credentials (aws or azure)")
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

// resolveCredentialDir returns the credential directory path (~/.tiam/creds),
// creating it if needed with 0700 permissions.
func resolveCredentialDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determining home directory: %w", err)
	}
	dir := filepath.Join(home, defaultDirName, credentialSubdir)

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("creating directory %s: %w", dir, err)
	}
	return dir, nil
}

func runTest() error {
	ctx := context.Background()

	fmt.Println("Initializing AWS broker...")
	broker, err := awsprovider.NewBroker(ctx)
	if err != nil {
		return fmt.Errorf("broker init failed: %w", err)
	}
	fmt.Printf("Account:    %s\n", broker.AccountID())
	fmt.Printf("Broker ARN: %s\n\n", broker.BrokerRoleARN())

	fmt.Println("Requesting S3 read-only access for 15m...")
	session, err := broker.GrantAccess(ctx, core.GrantAccessInput{
		Services: []string{"s3"},
		Level:    core.LevelReadOnly,
		TTL:      15 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("grant_access failed: %w", err)
	}

	fmt.Println("Credentials received:")
	fmt.Printf("  Session ID:        %s\n", session.ID)
	fmt.Printf("  Access Key ID:     %s\n", session.Credentials["AWS_ACCESS_KEY_ID"])
	fmt.Printf("  Secret Access Key: %s\n", core.Redact(session.Credentials["AWS_SECRET_ACCESS_KEY"], 4, 4))
	fmt.Printf("  Session Token:     %s\n", core.Redact(session.Credentials["AWS_SESSION_TOKEN"], 20, 0))
	fmt.Printf("  Expires At:        %s\n\n", session.ExpiresAt.Format(time.RFC3339))

	credentialDir, err := resolveCredentialDir()
	if err != nil {
		return fmt.Errorf("setting up credential directory: %w", err)
	}

	envFile := filepath.Join(credentialDir, fmt.Sprintf("test-%s.env", session.ID))
	content := strings.Join([]string{
		fmt.Sprintf("AWS_ACCESS_KEY_ID=%s", session.Credentials["AWS_ACCESS_KEY_ID"]),
		fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s", session.Credentials["AWS_SECRET_ACCESS_KEY"]),
		fmt.Sprintf("AWS_SESSION_TOKEN=%s", session.Credentials["AWS_SESSION_TOKEN"]),
	}, "\n") + "\n"
	if err := os.WriteFile(envFile, []byte(content), 0600); err != nil {
		return fmt.Errorf("writing credential file: %w", err)
	}

	fmt.Println("To verify, run:")
	fmt.Printf("  env $(cat %s) aws s3 ls\n", envFile)

	return nil
}

func runTestAzure() error {
	ctx := context.Background()

	fmt.Println("Initializing Azure broker...")
	broker, err := azureprovider.NewBroker(ctx)
	if err != nil {
		return fmt.Errorf("broker init failed: %w", err)
	}
	fmt.Printf("Subscription: %s\n", broker.SubscriptionID())
	fmt.Printf("Tenant:       %s\n\n", broker.TenantID())

	fmt.Println("Requesting storage read-only access for 15m...")
	session, err := broker.GrantAccess(ctx, core.GrantAccessInput{
		Services: []string{"storage"},
		Level:    core.LevelReadOnly,
		TTL:      15 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("grant_access failed: %w", err)
	}

	fmt.Println("Credentials received:")
	fmt.Printf("  Session ID:      %s\n", session.ID)
	fmt.Printf("  Client ID:       %s\n", session.Credentials["AZURE_CLIENT_ID"])
	fmt.Printf("  Client Secret:   %s\n", core.Redact(session.Credentials["AZURE_CLIENT_SECRET"], 4, 4))
	fmt.Printf("  Tenant ID:       %s\n", session.Credentials["AZURE_TENANT_ID"])
	fmt.Printf("  Subscription ID: %s\n", session.Credentials["AZURE_SUBSCRIPTION_ID"])
	fmt.Printf("  Expires At:      %s\n\n", session.ExpiresAt.Format(time.RFC3339))

	credentialDir, err := resolveCredentialDir()
	if err != nil {
		return fmt.Errorf("setting up credential directory: %w", err)
	}

	envFile := filepath.Join(credentialDir, fmt.Sprintf("test-%s.env", session.ID))
	content := strings.Join([]string{
		fmt.Sprintf("AZURE_CLIENT_ID=%s", session.Credentials["AZURE_CLIENT_ID"]),
		fmt.Sprintf("AZURE_CLIENT_SECRET=%s", session.Credentials["AZURE_CLIENT_SECRET"]),
		fmt.Sprintf("AZURE_TENANT_ID=%s", session.Credentials["AZURE_TENANT_ID"]),
		fmt.Sprintf("AZURE_SUBSCRIPTION_ID=%s", session.Credentials["AZURE_SUBSCRIPTION_ID"]),
	}, "\n") + "\n"
	if err := os.WriteFile(envFile, []byte(content), 0600); err != nil {
		return fmt.Errorf("writing credential file: %w", err)
	}

	fmt.Println("To verify, run:")
	fmt.Printf("  env $(cat %s) az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID\n", envFile)
	fmt.Println("  az storage account list --output table")

	// Clean up the role assignment.
	fmt.Println("\nCleaning up role assignment...")
	if err := broker.Cleanup(ctx, session); err != nil {
		return fmt.Errorf("cleanup failed: %w", err)
	}
	fmt.Println("Role assignment removed. Test complete.")

	return nil
}
