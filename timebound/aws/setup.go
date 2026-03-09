package aws

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/builder-magic/timebound-iam/timebound/core"
)

// RunSetup runs the interactive setup wizard that generates IAM policy JSON.
// An empty profile uses the default credential chain.
func RunSetup(profile string) error {
	ctx := context.Background()

	broker, err := NewBrokerWithProfile(ctx, profile)
	if err != nil {
		return fmt.Errorf("initializing broker: %w", err)
	}

	fmt.Printf("AWS Account:     %s\n", broker.AccountID())
	fmt.Printf("Broker Role ARN: %s\n\n", broker.BrokerRoleARN())

	services := ListServices()
	fmt.Println("Available services:")
	for i, svc := range services {
		fmt.Printf("  %2d. %-20s [%s]\n", i+1, svc.Name, strings.Join(svc.Levels, ", "))
	}

	fmt.Println("\nWhich services should the broker role allow?")
	fmt.Println("Enter numbers separated by commas (e.g. 1,2,5) or 'all':")
	fmt.Print("> ")

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return fmt.Errorf("no input received")
	}
	input := strings.TrimSpace(scanner.Text())

	selected := selectServices(services, input)
	if len(selected) == 0 {
		return fmt.Errorf("no services selected")
	}

	fmt.Printf("\nSelected services: %s\n\n", strings.Join(selected, ", "))

	trustPolicy := buildTrustPolicy(broker.AccountID())
	inlinePolicy := buildInlinePolicy(selected)

	trustJSON, err := json.MarshalIndent(trustPolicy, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling trust policy: %w", err)
	}

	inlineJSON, err := json.MarshalIndent(inlinePolicy, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling inline policy: %w", err)
	}

	fmt.Println("=" + strings.Repeat("=", 69))
	fmt.Println("STEP 1: Create the IAM role")
	fmt.Println("=" + strings.Repeat("=", 69))
	fmt.Println()
	fmt.Printf("Role name: %s\n\n", brokerRoleName)
	fmt.Println("Trust policy (paste into 'Trust relationships' tab):")
	fmt.Println()
	fmt.Println(string(trustJSON))
	fmt.Println()

	fmt.Println("=" + strings.Repeat("=", 69))
	fmt.Println("STEP 2: Add the inline policy")
	fmt.Println("=" + strings.Repeat("=", 69))
	fmt.Println()
	fmt.Println("Inline policy (paste into 'Permissions' > 'Add inline policy' > JSON):")
	fmt.Println()
	fmt.Println(string(inlineJSON))
	fmt.Println()

	fmt.Println("=" + strings.Repeat("=", 69))
	fmt.Println("STEP 3: Configure your MCP client")
	fmt.Println("=" + strings.Repeat("=", 69))
	fmt.Println()
	fmt.Println("Add to Claude Code:")
	fmt.Println("  claude mcp add timebound-iam -- /path/to/timebound-iam serve")
	fmt.Println()
	fmt.Println("Then restart Claude Code.")

	return nil
}

func selectServices(services []core.ServiceInfo, input string) []string {
	if strings.ToLower(input) == "all" {
		names := make([]string, len(services))
		for i, svc := range services {
			names[i] = svc.Name
		}
		return names
	}

	selected := make(map[string]bool)
	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		var idx int
		if _, err := fmt.Sscanf(part, "%d", &idx); err != nil {
			continue
		}
		if idx >= 1 && idx <= len(services) {
			selected[services[idx-1].Name] = true
		}
	}

	names := make([]string, 0, len(selected))
	for name := range selected {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// iamPolicy represents an IAM policy document.
type iamPolicy struct {
	Version   string         `json:"Version"`
	Statement []iamStatement `json:"Statement"`
}

type iamStatement struct {
	Effect    string     `json:"Effect"`
	Action    any        `json:"Action"`
	Resource  any        `json:"Resource,omitempty"`
	Principal *principal `json:"Principal,omitempty"`
}

type principal struct {
	AWS string `json:"AWS"`
}

func buildTrustPolicy(accountID string) iamPolicy {
	return iamPolicy{
		Version: "2012-10-17",
		Statement: []iamStatement{
			{
				Effect: "Allow",
				Action: "sts:AssumeRole",
				Principal: &principal{
					AWS: fmt.Sprintf("arn:aws:iam::%s:root", accountID),
				},
			},
		},
	}
}

func buildInlinePolicy(services []string) iamPolicy {
	actions := make([]string, 0, len(services)+1)
	actions = append(actions, "sts:AssumeRole")

	for _, svc := range services {
		if prefix, err := GetIAMPrefix(svc); err == nil {
			actions = append(actions, prefix+":*")
		}
	}
	sort.Strings(actions)

	return iamPolicy{
		Version: "2012-10-17",
		Statement: []iamStatement{
			{
				Effect:   "Allow",
				Action:   actions,
				Resource: "*",
			},
		},
	}
}
