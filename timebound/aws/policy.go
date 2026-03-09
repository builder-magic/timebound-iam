package aws

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/builder-magic/timebound-iam/timebound/core"
)

// ServicePolicy holds the managed policy ARNs and IAM action prefix for a single AWS service.
type ServicePolicy struct {
	IAMPrefix string `json:"iam_prefix"`
	ReadOnly  string `json:"read_only,omitempty"`
	Full      string `json:"full,omitempty"`
}

//go:embed policies.json
var policiesJSON []byte

// policyRegistry holds the parsed service -> policy mapping.
var policyRegistry map[string]ServicePolicy

func init() {
	if err := json.Unmarshal(policiesJSON, &policyRegistry); err != nil {
		panic(fmt.Sprintf("failed to parse embedded policies.json: %v", err))
	}
}

// GetPolicyARN returns the managed policy ARN for a given service and access level.
// Service names are normalized to lowercase with whitespace trimmed.
func GetPolicyARN(service, level string) (string, error) {
	service = strings.ToLower(strings.TrimSpace(service))
	svc, ok := policyRegistry[service]
	if !ok {
		return "", fmt.Errorf("unknown service: %s", service)
	}

	switch level {
	case core.LevelReadOnly:
		if svc.ReadOnly == "" {
			return "", fmt.Errorf("service %s does not support %s access", service, level)
		}
		return svc.ReadOnly, nil
	case core.LevelFull:
		if svc.Full == "" {
			return "", fmt.Errorf("service %s does not support %s access", service, level)
		}
		return svc.Full, nil
	default:
		return "", fmt.Errorf("invalid access level: %s (must be %s or %s)", level, core.LevelReadOnly, core.LevelFull)
	}
}

// GetPolicyARNs returns managed policy ARNs for multiple services at a given access level.
// Duplicate service names are silently deduplicated to avoid sending duplicate
// PolicyArns to STS AssumeRole.
func GetPolicyARNs(services []string, level string) ([]string, error) {
	seen := make(map[string]bool, len(services))
	arns := make([]string, 0, len(services))
	for _, svc := range services {
		svc = strings.ToLower(strings.TrimSpace(svc))
		if seen[svc] {
			continue
		}
		seen[svc] = true
		arn, err := GetPolicyARN(svc, level)
		if err != nil {
			return nil, err
		}
		arns = append(arns, arn)
	}
	return arns, nil
}

// ListServices returns all available AWS services sorted by name.
func ListServices() []core.ServiceInfo {
	services := make([]core.ServiceInfo, 0, len(policyRegistry))
	for name, policy := range policyRegistry {
		info := core.ServiceInfo{Name: name}
		if policy.ReadOnly != "" {
			info.Levels = append(info.Levels, core.LevelReadOnly)
		}
		if policy.Full != "" {
			info.Levels = append(info.Levels, core.LevelFull)
		}
		services = append(services, info)
	}
	sort.Slice(services, func(i, j int) bool {
		return services[i].Name < services[j].Name
	})
	return services
}

// GetIAMPrefix returns the IAM action prefix for a given service name.
// Service names are normalized to lowercase with whitespace trimmed.
func GetIAMPrefix(service string) (string, error) {
	service = strings.ToLower(strings.TrimSpace(service))
	svc, ok := policyRegistry[service]
	if !ok {
		return "", fmt.Errorf("unknown service: %s", service)
	}
	return svc.IAMPrefix, nil
}

// ValidateServices checks that all provided service names exist in the registry.
func ValidateServices(services []string) error {
	// An empty services list must be rejected. STS AssumeRole called without
	// PolicyArns grants the full, unscoped permissions of the broker role.
	if len(services) == 0 {
		return fmt.Errorf("at least one service is required")
	}

	var unknown []string
	for _, svc := range services {
		svc = strings.ToLower(strings.TrimSpace(svc))
		if _, ok := policyRegistry[svc]; !ok {
			unknown = append(unknown, svc)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("unknown services: %s", strings.Join(unknown, ", "))
	}
	return nil
}
