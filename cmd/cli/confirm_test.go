package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/builder-magic/timebound-iam/timebound/core"
)

func testParams() SummaryParams {
	return SummaryParams{
		Account: "123456789012",
		Role:    "arn:aws:iam::123456789012:role/timebound-iam-broker",
		TTL:     15 * time.Minute,
		Scopes: []core.ServiceScope{
			{Service: "s3", Level: core.LevelReadOnly},
		},
	}
}

func TestConfirmOrAbortDryRun(t *testing.T) {
	var buf bytes.Buffer
	err := ConfirmOrAbort(&buf, strings.NewReader(""), testParams(), true, false)
	if !errors.Is(err, ErrDryRun) {
		t.Errorf("expected ErrDryRun, got %v", err)
	}
	// Summary table should still be rendered.
	if !strings.Contains(buf.String(), "Account") {
		t.Error("summary table not rendered for dry run")
	}
}

func TestConfirmOrAbortNoConfirm(t *testing.T) {
	var buf bytes.Buffer
	err := ConfirmOrAbort(&buf, strings.NewReader(""), testParams(), false, true)
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestConfirmOrAbortDryRunTakesPrecedence(t *testing.T) {
	var buf bytes.Buffer
	err := ConfirmOrAbort(&buf, strings.NewReader(""), testParams(), true, true)
	if !errors.Is(err, ErrDryRun) {
		t.Errorf("dry-run should take precedence over no-confirm, got %v", err)
	}
}
