package azure

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// RunSetup runs the automated Azure setup.
// It creates two service principals using the az CLI:
//   - Manager SP: has "User Access Administrator" to manage role assignments
//   - Worker SP: starts with no permissions, receives temporary role assignments
func RunSetup() error {
	fmt.Println("Azure Setup for timebound-iam")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()

	// Verify az CLI is available and logged in.
	if err := verifyAzCLI(); err != nil {
		return err
	}

	// Step 1: Get subscription ID.
	fmt.Println("[1/4] Getting subscription ID...")
	subscriptionID, err := azCmd("account", "show", "--query", "id", "-o", "tsv")
	if err != nil {
		return fmt.Errorf("getting subscription ID: %w\nMake sure you are logged in: az login", err)
	}
	fmt.Printf("  Subscription: %s\n\n", subscriptionID)

	// Step 2: Create manager SP with User Access Administrator.
	fmt.Println("[2/4] Creating manager service principal...")
	scope := fmt.Sprintf("/subscriptions/%s", subscriptionID)
	managerJSON, err := azCmd("ad", "sp", "create-for-rbac",
		"--name", "timebound-iam-manager",
		"--role", "User Access Administrator",
		"--scopes", scope)
	if err != nil {
		return fmt.Errorf("creating manager SP: %w", err)
	}

	managerSP, err := parseSPOutput(managerJSON)
	if err != nil {
		return fmt.Errorf("parsing manager SP output: %w", err)
	}
	fmt.Printf("  Manager SP created: %s\n\n", managerSP.appID)

	// Step 3: Create worker SP with no permissions.
	fmt.Println("[3/4] Creating worker service principal...")
	workerJSON, err := azCmd("ad", "sp", "create-for-rbac",
		"--name", "timebound-iam-worker",
		"--skip-assignment")
	if err != nil {
		return fmt.Errorf("creating worker SP: %w", err)
	}

	workerSP, err := parseSPOutput(workerJSON)
	if err != nil {
		return fmt.Errorf("parsing worker SP output: %w", err)
	}
	fmt.Printf("  Worker SP created: %s\n\n", workerSP.appID)

	// Step 4: Get worker SP object ID.
	fmt.Println("[4/4] Getting worker SP object ID...")
	workerObjectID, err := azCmd("ad", "sp", "show",
		"--id", workerSP.appID,
		"--query", "id",
		"-o", "tsv")
	if err != nil {
		return fmt.Errorf("getting worker object ID: %w", err)
	}
	fmt.Printf("  Worker Object ID: %s\n\n", workerObjectID)

	// Save config.
	cfg := &Config{
		TenantID:            managerSP.tenant,
		SubscriptionID:      subscriptionID,
		ManagerClientID:     managerSP.appID,
		ManagerClientSecret: managerSP.password,
		WorkerClientID:      workerSP.appID,
		WorkerClientSecret:  workerSP.password,
		WorkerObjectID:      workerObjectID,
	}

	if err := SaveConfig(cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	path, _ := configPath()
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("Setup complete!")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()
	fmt.Printf("Configuration saved to: %s\n\n", path)
	fmt.Println("How it works:")
	fmt.Println("  - Manager SP (timebound-iam-manager) creates/removes role assignments")
	fmt.Println("  - Worker SP (timebound-iam-worker) starts with NO permissions")
	fmt.Println("  - grant_access creates temporary role assignments on the worker SP")
	fmt.Println("  - Expired sessions have their role assignments automatically removed")
	fmt.Println()
	fmt.Println("You can now safely run: az logout")
	fmt.Println("The broker authenticates as the manager SP, not your personal account.")

	return nil
}

// verifyAzCLI checks that the az CLI is installed and the user is logged in.
func verifyAzCLI() error {
	if _, err := exec.LookPath("az"); err != nil {
		return fmt.Errorf("az CLI not found. Install it: https://learn.microsoft.com/en-us/cli/azure/install-azure-cli")
	}
	if _, err := azCmd("account", "show", "--query", "id", "-o", "tsv"); err != nil {
		return fmt.Errorf("not logged in to Azure. Run: az login")
	}
	return nil
}

// azCmd runs an az CLI command and returns the trimmed stdout.
func azCmd(args ...string) (string, error) {
	cmd := exec.Command("az", args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("%s\n%s", err, string(exitErr.Stderr))
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

type spOutput struct {
	appID    string
	password string
	tenant   string
}

func parseSPOutput(jsonStr string) (*spOutput, error) {
	var raw struct {
		AppID    string `json:"appId"`
		Password string `json:"password"`
		Tenant   string `json:"tenant"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if raw.AppID == "" || raw.Password == "" || raw.Tenant == "" {
		return nil, fmt.Errorf("incomplete output: need appId, password, and tenant")
	}
	return &spOutput{
		appID:    raw.AppID,
		password: raw.Password,
		tenant:   raw.Tenant,
	}, nil
}
