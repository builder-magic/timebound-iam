package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	awsprovider "github.com/builder-magic/timebound-iam/timebound/aws"
	"github.com/builder-magic/timebound-iam/timebound/core"
)

const (
	envKeyAccessKeyID     = "AWS_ACCESS_KEY_ID"
	envKeySecretAccessKey = "AWS_SECRET_ACCESS_KEY"
	envKeySessionToken    = "AWS_SESSION_TOKEN"
)

// RunEnv implements the "env" subcommand. It prints export statements for
// temporary AWS credentials, or unset statements when --unset is given.
func RunEnv(args []string) error {
	fs := flag.NewFlagSet("env", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Print export/unset statements for cloud credentials")
		fmt.Fprintln(fs.Output(), "")
		fmt.Fprintln(fs.Output(), "USAGE")
		fmt.Fprintln(fs.Output(), "  timebound-iam env [flags]")
		fmt.Fprintln(fs.Output(), "  eval \"$(timebound-iam env -s s3:ro -t 15m --no-confirm)\"")
		fmt.Fprintln(fs.Output(), "  eval \"$(timebound-iam env --unset)\"")
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
	unset := fs.Bool("unset", false, "print unset statements to clear AWS credential env vars")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	// --unset is a standalone path that needs no validation or broker.
	if *unset {
		fmt.Fprintf(os.Stdout, "unset %s\n", envKeyAccessKeyID)
		fmt.Fprintf(os.Stdout, "unset %s\n", envKeySecretAccessKey)
		fmt.Fprintf(os.Stdout, "unset %s\n", envKeySessionToken)
		return nil
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
	broker, err := awsprovider.NewBrokerWithProfile(ctx, *profile)
	if err != nil {
		return fmt.Errorf("initializing broker: %w", err)
	}

	params := SummaryParams{
		Account: broker.AccountID(),
		Role:    broker.BrokerRoleARN(),
		Profile: *profile,
		TTL:     ttl,
		Scopes:  scopes.scopes,
	}

	if err := ConfirmOrAbort(os.Stderr, os.Stdin, params, *dryRun, *noConfirm); err != nil {
		if errors.Is(err, ErrDryRun) {
			fmt.Fprintln(os.Stderr, err)
			return nil
		}
		return err
	}

	session, err := broker.GrantAccess(ctx, core.GrantAccessInput{
		ServiceScopes: scopes.scopes,
		TTL:           ttl,
		Profile:       *profile,
	})
	if err != nil {
		return fmt.Errorf("granting access: %w", err)
	}

	// Sort credential keys for deterministic output.
	keys := make([]string, 0, len(session.Credentials))
	for k := range session.Credentials {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(os.Stdout, "export %s=%s\n", k, session.Credentials[k])
	}
	return nil
}
