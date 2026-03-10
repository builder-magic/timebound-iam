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
// Each level may require multiple roles (e.g. Reader + data-plane role).
type RoleMapping struct {
	DisplayName string   `json:"display_name"`
	ReadOnly    []string `json:"read_only,omitempty"`
	Full        []string `json:"full,omitempty"`
}

//go:embed policies.json
var policiesJSON []byte

var roleRegistry map[string]RoleMapping

func init() {
	if err := json.Unmarshal(policiesJSON, &roleRegistry); err != nil {
		panic(fmt.Sprintf("failed to parse embedded azure policies.json: %v", err))
	}
}

// GetRoleDefinitionIDs returns the Azure built-in role definition IDs for a
// given service and access level. Some services require multiple roles
// (e.g. Reader for management plane + a data-plane role).
func GetRoleDefinitionIDs(services []string, level string) ([]string, error) {
	seen := make(map[string]bool)
	var ids []string
	for _, svc := range services {
		svc = strings.ToLower(strings.TrimSpace(svc))
		roleIDs, err := getRoleIDs(svc, level)
		if err != nil {
			return nil, err
		}
		for _, id := range roleIDs {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids, nil
}

// getRoleIDs returns the role definition IDs for a single service and level.
func getRoleIDs(service, level string) ([]string, error) {
	role, ok := roleRegistry[service]
	if !ok {
		return nil, fmt.Errorf("unknown Azure service: %s", service)
	}

	switch level {
	case core.LevelReadOnly:
		if len(role.ReadOnly) == 0 {
			return nil, fmt.Errorf("Azure service %s does not support %s access", service, level)
		}
		return role.ReadOnly, nil
	case core.LevelFull:
		if len(role.Full) == 0 {
			return nil, fmt.Errorf("Azure service %s does not support %s access", service, level)
		}
		return role.Full, nil
	default:
		return nil, fmt.Errorf("invalid access level: %s (must be %s or %s)", level, core.LevelReadOnly, core.LevelFull)
	}
}

// ListServices returns all available Azure services sorted by name.
func ListServices() []core.ServiceInfo {
	services := make([]core.ServiceInfo, 0, len(roleRegistry))
	for name, role := range roleRegistry {
		info := core.ServiceInfo{Name: name}
		if len(role.ReadOnly) > 0 {
			info.Levels = append(info.Levels, core.LevelReadOnly)
		}
		if len(role.Full) > 0 {
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

	seen := make(map[string]bool)
	var ids []string
	for _, s := range scopes {
		roleIDs, err := getRoleIDs(s.Service, s.Level)
		if err != nil {
			return nil, err
		}
		for _, id := range roleIDs {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids, nil
}
