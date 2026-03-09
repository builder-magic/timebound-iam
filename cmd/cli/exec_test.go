package cli

import (
	"strings"
	"testing"
)

func TestFilterCredentialEnv(t *testing.T) {
	environ := []string{
		"HOME=/home/user",
		"PATH=/usr/bin",
		"AWS_ACCESS_KEY_ID=old-key",
		"AWS_SECRET_ACCESS_KEY=old-secret",
		"AWS_SESSION_TOKEN=old-token",
		"AWS_REGION=us-east-1",
		"TERM=xterm",
	}

	filtered := filterCredentialEnv(environ)

	// Should keep non-credential vars.
	wantKept := []string{"HOME=/home/user", "PATH=/usr/bin", "AWS_REGION=us-east-1", "TERM=xterm"}
	for _, want := range wantKept {
		found := false
		for _, got := range filtered {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q in filtered env", want)
		}
	}

	// Should remove credential vars.
	wantRemoved := []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"}
	for _, key := range wantRemoved {
		for _, got := range filtered {
			if strings.HasPrefix(got, key+"=") {
				t.Errorf("expected %q to be removed from filtered env", key)
			}
		}
	}

	if len(filtered) != 4 {
		t.Errorf("expected 4 env vars, got %d", len(filtered))
	}
}

func TestFilterCredentialEnvAzure(t *testing.T) {
	environ := []string{
		"HOME=/home/user",
		"AZURE_CLIENT_ID=old-client",
		"AZURE_CLIENT_SECRET=old-secret",
		"AZURE_TENANT_ID=old-tenant",
		"AZURE_SUBSCRIPTION_ID=old-sub",
	}

	filtered := filterCredentialEnv(environ)

	if len(filtered) != 1 {
		t.Errorf("expected 1 env var, got %d: %v", len(filtered), filtered)
	}
	if filtered[0] != "HOME=/home/user" {
		t.Errorf("expected HOME, got %q", filtered[0])
	}
}

func TestRunExecMissingCommand(t *testing.T) {
	err := RunExec([]string{"-s", "s3:ro", "-t", "15m", "--no-confirm"})
	if err == nil {
		t.Fatal("expected error for missing command")
	}
	if !strings.Contains(err.Error(), "no command specified") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunExecMissingScope(t *testing.T) {
	err := RunExec([]string{"-t", "15m", "--", "echo", "hello"})
	if err == nil {
		t.Fatal("expected error for missing scope")
	}
	if !strings.Contains(err.Error(), "--scope / -s is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunExecMissingTTL(t *testing.T) {
	err := RunExec([]string{"-s", "s3:ro", "--", "echo", "hello"})
	if err == nil {
		t.Fatal("expected error for missing TTL")
	}
	if !strings.Contains(err.Error(), "--ttl / -t is required") {
		t.Errorf("unexpected error: %v", err)
	}
}
