package cli

import (
	"fmt"
	"strings"

	"github.com/builder-magic/timebound-iam/timebound/core"
)

// scopeFlag implements flag.Value for parsing repeated/comma-separated
// service:level pairs (e.g. -s s3:ro,dynamodb:full -s lambda:ro).
type scopeFlag struct {
	scopes []core.ServiceScope
}

func (f *scopeFlag) String() string {
	parts := make([]string, len(f.scopes))
	for i, s := range f.scopes {
		parts[i] = s.Service + ":" + s.Level
	}
	return strings.Join(parts, ",")
}

func (f *scopeFlag) Set(val string) error {
	var parsed []core.ServiceScope
	for _, item := range strings.Split(val, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		scope, err := parseScope(item)
		if err != nil {
			return err
		}
		parsed = append(parsed, scope)
	}
	f.scopes = append(f.scopes, parsed...)
	return nil
}

// parseScope parses a single "service:level" string into a ServiceScope.
func parseScope(s string) (core.ServiceScope, error) {
	idx := strings.IndexByte(s, ':')
	if idx < 0 {
		return core.ServiceScope{}, fmt.Errorf("invalid scope %q: expected service:level (e.g. s3:ro)", s)
	}
	service := strings.TrimSpace(s[:idx])
	level := strings.TrimSpace(s[idx+1:])

	if service == "" {
		return core.ServiceScope{}, fmt.Errorf("invalid scope %q: service name is empty", s)
	}
	if level == "" {
		return core.ServiceScope{}, fmt.Errorf("invalid scope %q: level is empty", s)
	}

	expanded, err := expandLevel(level)
	if err != nil {
		return core.ServiceScope{}, fmt.Errorf("invalid scope %q: %w", s, err)
	}

	return core.ServiceScope{
		Service: strings.ToLower(service),
		Level:   expanded,
	}, nil
}

// expandLevel maps shorthand aliases to canonical level constants.
func expandLevel(level string) (string, error) {
	switch strings.ToLower(level) {
	case "ro", "read_only", "readonly":
		return core.LevelReadOnly, nil
	case "full":
		return core.LevelFull, nil
	default:
		return "", fmt.Errorf("unknown level %q (use ro, read_only, or full)", level)
	}
}
