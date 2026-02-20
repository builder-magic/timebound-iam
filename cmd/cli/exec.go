package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	timebound "github.com/builder-magic/timebound-iam/timebound/aws"
)

// RunExec implements the "exec" subcommand. It acquires temporary credentials
// and runs a child command with those credentials injected into its environment.
func RunExec(args []string) error {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Run a command with temporary AWS credentials")
		fmt.Fprintln(fs.Output(), "")
		fmt.Fprintln(fs.Output(), "USAGE")
		fmt.Fprintln(fs.Output(), "  timebound-iam exec [flags] -- <command> [args...]")
		fmt.Fprintln(fs.Output(), "")
		fmt.Fprintln(fs.Output(), "FLAGS")
		fs.PrintDefaults()
	}

	var scopes scopeFlag
	fs.Var(&scopes, "s", "service:level scope (repeatable, comma-separated)")
	fs.Var(&scopes, "scope", "service:level scope (repeatable, comma-separated)")

	var ttlStr string
	fs.StringVar(&ttlStr, "t", "", "credential TTL (e.g. 15m, 1h)")
	fs.StringVar(&ttlStr, "ttl", "", "credential TTL (e.g. 15m, 1h)")

	profile := fs.String("profile", "", "AWS profile name")
	dryRun := fs.Bool("dry-run", false, "show summary and exit without requesting credentials")
	noConfirm := fs.Bool("no-confirm", false, "skip confirmation prompt")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	// Everything after flag parsing is the child command.
	childArgs := fs.Args()
	if len(childArgs) == 0 {
		return fmt.Errorf("no command specified; usage: timebound-iam exec [flags] -- <command> [args...]")
	}

	if ttlStr == "" {
		return fmt.Errorf("--ttl / -t is required")
	}
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return fmt.Errorf("invalid TTL %q: %w", ttlStr, err)
	}

	if len(scopes.scopes) == 0 {
		return fmt.Errorf("--scope / -s is required (e.g. -s s3:ro)")
	}

	if err := validateInputs(scopes.scopes, ttl); err != nil {
		return err
	}

	ctx := context.Background()
	broker, err := timebound.NewBrokerWithProfile(ctx, *profile)
	if err != nil {
		return fmt.Errorf("initializing broker: %w", err)
	}

	params := SummaryParams{
		Account: broker.AccountID(),
		Role:    broker.BrokerRoleARN(),
		Profile: *profile,
		TTL:     ttl,
		Scopes:  scopes.scopes,
		Command: childArgs,
	}

	if err := ConfirmOrAbort(os.Stderr, os.Stdin, params, *dryRun, *noConfirm); err != nil {
		if errors.Is(err, ErrDryRun) {
			fmt.Fprintln(os.Stderr, err)
			return nil
		}
		return err
	}

	session, err := broker.GrantAccess(ctx, timebound.GrantAccessInput{
		ServiceScopes: scopes.scopes,
		TTL:           ttl,
		Profile:       *profile,
	})
	if err != nil {
		return fmt.Errorf("granting access: %w", err)
	}

	return execChild(ctx, childArgs, session)
}

// execChild runs the child command with AWS credentials injected into the
// environment. Existing AWS credential env vars are filtered out first.
func execChild(ctx context.Context, childArgs []string, session *timebound.Session) error {
	env := filterAWSEnv(os.Environ())
	env = append(env,
		envKeyAccessKeyID+"="+session.AccessKeyID,
		envKeySecretAccessKey+"="+session.SecretAccessKey,
		envKeySessionToken+"="+session.SessionToken,
	)

	cmd := exec.CommandContext(ctx, childArgs[0], childArgs[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("running command: %w", err)
	}
	return nil
}

// filterAWSEnv returns a copy of environ with AWS credential variables removed.
func filterAWSEnv(environ []string) []string {
	filtered := make([]string, 0, len(environ))
	for _, e := range environ {
		key := e
		if idx := strings.IndexByte(e, '='); idx >= 0 {
			key = e[:idx]
		}
		switch key {
		case envKeyAccessKeyID, envKeySecretAccessKey, envKeySessionToken:
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}
