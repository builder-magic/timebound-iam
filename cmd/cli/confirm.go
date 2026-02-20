package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ErrDryRun is returned when --dry-run is set to signal a clean abort.
var ErrDryRun = errors.New("dry run complete, no changes made")

// ConfirmOrAbort renders the summary table and optionally prompts for
// confirmation. It returns nil to proceed, ErrDryRun for dry-run, or
// an error if the user declines or stdin is not a TTY.
func ConfirmOrAbort(w io.Writer, r io.Reader, params SummaryParams, dryRun, noConfirm bool) error {
	RenderSummary(w, params)

	if dryRun {
		return ErrDryRun
	}
	if noConfirm {
		return nil
	}

	if !isTerminal() {
		return fmt.Errorf("stdin is not a terminal; use --no-confirm for non-interactive use")
	}

	fmt.Fprint(w, "\nProceed? [y/N] ")
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("reading input: %w", err)
		}
		return fmt.Errorf("no input received")
	}
	answer := strings.TrimSpace(scanner.Text())
	if strings.ToLower(answer) != "y" {
		return fmt.Errorf("aborted by user")
	}
	return nil
}

// isTerminal reports whether stdin is connected to a terminal.
func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
