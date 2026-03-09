package cli

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/builder-magic/timebound-iam/timebound/core"
)

// SummaryParams holds the data displayed in the pre-confirmation summary table.
type SummaryParams struct {
	Account string
	Role    string
	Profile string
	TTL     time.Duration
	Scopes  []core.ServiceScope
	Command []string // non-empty only for exec
}

// RenderSummary writes a box-drawing summary table to w.
func RenderSummary(w io.Writer, p SummaryParams) {
	const labelWidth = 10 // width of label column including padding

	// Collect rows as label/value pairs.
	type row struct {
		label string
		value string
	}
	var rows []row

	rows = append(rows, row{"Account", p.Account})
	rows = append(rows, row{"Role", p.Role})
	if p.Profile != "" {
		rows = append(rows, row{"Profile", p.Profile})
	}
	rows = append(rows, row{"TTL", formatTTL(p.TTL)})

	for _, s := range p.Scopes {
		rows = append(rows, row{"Scope", s.Service + ":" + s.Level})
	}

	if len(p.Command) > 0 {
		rows = append(rows, row{"Command", strings.Join(p.Command, " ")})
	}

	// Determine the widest value for box sizing.
	maxVal := 0
	for _, r := range rows {
		if len(r.value) > maxVal {
			maxVal = len(r.value)
		}
	}
	// Ensure minimum total inner width = labelWidth + maxVal.
	innerWidth := labelWidth + maxVal

	// Box drawing.
	hLine := strings.Repeat("─", innerWidth+2) // +2 for padding spaces
	fmt.Fprintf(w, "┌%s┐\n", hLine)
	for _, r := range rows {
		pad := innerWidth - labelWidth - len(r.value)
		if pad < 0 {
			pad = 0
		}
		fmt.Fprintf(w, "│ %-*s%s%s │\n", labelWidth, r.label, r.value, strings.Repeat(" ", pad))
	}
	fmt.Fprintf(w, "└%s┘\n", hLine)
}

// formatTTL returns a human-readable duration string.
func formatTTL(d time.Duration) string {
	if d >= time.Hour {
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	}
	return fmt.Sprintf("%dm", int(d.Minutes()))
}
