package azure

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/builder-magic/timebound-iam/timebound/core"
)

// RoleMapping holds the Azure built-in role definition IDs for a service.
type RoleMapping struct {
	DisplayName string `json:"display_name"`
	ReadOnly    string `json:"read_only,omitempty"`
	Full        string `json:"full,omitempty"`
}

//go:embed policies.json
var policiesJSON []byte

var roleRegistry map[string]RoleMapping

func init() {
	if err := json.Unmarshal(policiesJSON, &roleRegistry); err != nil {
		panic(fmt.Sprintf("failed to parse embedded azure policies.json: %v", err))
	}
}

// GetRoleDefinitionID returns the Azure built-in role definition ID for a
// given service and access level.
func GetRoleDefinitionID(service, level string) (string, error) {
	service = strings.ToLower(strings.TrimSpace(service))
	role, ok := roleRegistry[service]
	if !ok {
		return "", fmt.Errorf("unknown Azure service: %s", service)
	}

	switch level {
	case core.LevelReadOnly:
		if role.ReadOnly == "" {
			return "", fmt.Errorf("Azure service %s does not support %s access", service, level)
		}
		return role.ReadOnly, nil
	case core.LevelFull:
		if role.Full == "" {
			return "", fmt.Errorf("Azure service %s does not support %s access", service, level)
		}
		return role.Full, nil
	default:
		return "", fmt.Errorf("invalid access level: %s (must be %s or %s)", level, core.LevelReadOnly, core.LevelFull)
	}
}

// GetRoleDefinitionIDs returns role definition IDs for multiple services.
func GetRoleDefinitionIDs(services []string, level string) ([]string, error) {
	seen := make(map[string]bool, len(services))
	ids := make([]string, 0, len(services))
	for _, svc := range services {
		svc = strings.ToLower(strings.TrimSpace(svc))
		if seen[svc] {
			continue
		}
		seen[svc] = true
		id, err := GetRoleDefinitionID(svc, level)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// ListServices returns all available Azure services sorted by name.
func ListServices() []core.ServiceInfo {
	services := make([]core.ServiceInfo, 0, len(roleRegistry))
	for name, role := range roleRegistry {
		info := core.ServiceInfo{Name: name}
		if role.ReadOnly != "" {
			info.Levels = append(info.Levels, core.LevelReadOnly)
		}
		if role.Full != "" {
			info.Levels = append(info.Levels, core.LevelFull)
		}
		services = append(services, info)
	}
	sort.Slice(services, func(i, j int) bool {
		return services[i].Name < services[j].Name
	})
	return services
}

// ValidateServices checks that all provided service names exist in the Azure registry.
func ValidateServices(services []string) error {
	if len(services) == 0 {
		return fmt.Errorf("at least one service is required")
	}

	var unknown []string
	for _, svc := range services {
		svc = strings.ToLower(strings.TrimSpace(svc))
		if _, ok := roleRegistry[svc]; !ok {
			unknown = append(unknown, svc)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("unknown Azure services: %s", strings.Join(unknown, ", "))
	}
	return nil
}

// resolveScopedRoleIDs resolves role definition IDs from per-service scopes.
func resolveScopedRoleIDs(scopes []core.ServiceScope) ([]string, error) {
	services := make([]string, len(scopes))
	for i, s := range scopes {
		services[i] = s.Service
	}
	if err := ValidateServices(services); err != nil {
		return nil, err
	}

	seen := make(map[string]bool, len(scopes))
	ids := make([]string, 0, len(scopes))
	for _, s := range scopes {
		id, err := GetRoleDefinitionID(s.Service, s.Level)
		if err != nil {
			return nil, err
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids, nil
}
