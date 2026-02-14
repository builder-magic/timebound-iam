package timebound

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const (
	LevelReadOnly = "read_only"
	LevelFull     = "full"
)

// ServicePolicy holds the managed policy ARNs and IAM action prefix for a single AWS service.
type ServicePolicy struct {
	IAMPrefix string `json:"iam_prefix"`
	ReadOnly  string `json:"read_only,omitempty"`
	Full      string `json:"full,omitempty"`
}

// ServiceInfo describes an available service and its supported access levels.
type ServiceInfo struct {
	Name   string   `json:"name"`
	Levels []string `json:"levels"`
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
func GetPolicyARN(service, level string) (string, error) {
	svc, ok := policyRegistry[service]
	if !ok {
		return "", fmt.Errorf("unknown service: %s", service)
	}

	switch level {
	case LevelReadOnly:
		if svc.ReadOnly == "" {
			return "", fmt.Errorf("service %s does not support %s access", service, level)
		}
		return svc.ReadOnly, nil
	case LevelFull:
		if svc.Full == "" {
			return "", fmt.Errorf("service %s does not support %s access", service, level)
		}
		return svc.Full, nil
	default:
		return "", fmt.Errorf("invalid access level: %s (must be %s or %s)", level, LevelReadOnly, LevelFull)
	}
}

// GetPolicyARNs returns managed policy ARNs for multiple services at a given access level.
func GetPolicyARNs(services []string, level string) ([]string, error) {
	arns := make([]string, 0, len(services))
	for _, svc := range services {
		arn, err := GetPolicyARN(svc, level)
		if err != nil {
			return nil, err
		}
		arns = append(arns, arn)
	}
	return arns, nil
}

// ListServices returns all available services sorted by name.
func ListServices() []ServiceInfo {
	services := make([]ServiceInfo, 0, len(policyRegistry))
	for name, policy := range policyRegistry {
		info := ServiceInfo{Name: name}
		if policy.ReadOnly != "" {
			info.Levels = append(info.Levels, LevelReadOnly)
		}
		if policy.Full != "" {
			info.Levels = append(info.Levels, LevelFull)
		}
		services = append(services, info)
	}
	sort.Slice(services, func(i, j int) bool {
		return services[i].Name < services[j].Name
	})
	return services
}

// GetIAMPrefix returns the IAM action prefix for a given service name.
func GetIAMPrefix(service string) (string, error) {
	svc, ok := policyRegistry[service]
	if !ok {
		return "", fmt.Errorf("unknown service: %s", service)
	}
	return svc.IAMPrefix, nil
}

// ValidateServices checks that all provided service names exist in the registry.
func ValidateServices(services []string) error {
	var unknown []string
	for _, svc := range services {
		if _, ok := policyRegistry[svc]; !ok {
			unknown = append(unknown, svc)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("unknown services: %s", strings.Join(unknown, ", "))
	}
	return nil
}
