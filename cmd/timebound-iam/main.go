package main

import (
	"context"
	"fmt"
	"log"
	"os"
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
			fmt.Fprintln(os.Stderr, "usage: timebound-iam setup aws")
			os.Exit(1)
		}
		if err := timebound.RunSetup(); err != nil {
			log.Fatalf("setup: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func runServe() error {
	ctx := context.Background()

	store := timebound.NewSessionStore()
	lazyBroker := timebound.NewLazyBroker()

	server := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: serverVersion,
	}, nil)

	timebound.RegisterTools(server, lazyBroker, store)

	log.Printf("starting %s %s MCP server (broker initialized on first use)", serverName, serverVersion)

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
	fmt.Printf("  Secret Access Key: %s...%s\n", session.SecretAccessKey[:4], session.SecretAccessKey[len(session.SecretAccessKey)-4:])
	fmt.Printf("  Session Token:     %s...\n", session.SessionToken[:20])
	fmt.Printf("  Expires At:        %s\n\n", session.ExpiresAt.Format(time.RFC3339))

	fmt.Println("To verify, run:")
	fmt.Printf("  export AWS_ACCESS_KEY_ID=%s\n", session.AccessKeyID)
	fmt.Printf("  export AWS_SECRET_ACCESS_KEY=%s\n", session.SecretAccessKey)
	fmt.Printf("  export AWS_SESSION_TOKEN=%s\n", session.SessionToken)
	fmt.Println("  aws s3 ls")

	return nil
}
