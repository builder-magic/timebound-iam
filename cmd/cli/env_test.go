package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestRunEnvUnset(t *testing.T) {
	// Capture stdout by redirecting it.
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	runErr := RunEnv([]string{"--unset"})

	w.Close()
	os.Stdout = old

	if runErr != nil {
		t.Fatalf("unexpected error: %v", runErr)
	}

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	for _, key := range []string{envKeyAccessKeyID, envKeySecretAccessKey, envKeySessionToken} {
		expected := "unset " + key
		if !strings.Contains(output, expected) {
			t.Errorf("output missing %q:\n%s", expected, output)
		}
	}
}

func TestRunEnvMissingScope(t *testing.T) {
	err := RunEnv([]string{"-t", "15m"})
	if err == nil {
		t.Fatal("expected error for missing scope")
	}
	if !strings.Contains(err.Error(), "--scope / -s is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunEnvMissingTTL(t *testing.T) {
	err := RunEnv([]string{"-s", "s3:ro"})
	if err == nil {
		t.Fatal("expected error for missing TTL")
	}
	if !strings.Contains(err.Error(), "--ttl / -t is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunEnvInvalidTTL(t *testing.T) {
	err := RunEnv([]string{"-s", "s3:ro", "-t", "notaduration"})
	if err == nil {
		t.Fatal("expected error for invalid TTL")
	}
	if !strings.Contains(err.Error(), "invalid TTL") {
		t.Errorf("unexpected error: %v", err)
	}
}
