package azure

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	configDirName  = ".tiam"
	configFileName = "azure.json"
)

// Config holds the credentials for both the manager and worker service
// principals. The manager SP has "User Access Administrator" role and is
// used server-side to create/delete RBAC role assignments. The worker SP
// starts with no permissions and receives temporary role assignments;
// its credentials are handed out to sessions.
//
// This design means the user can `az logout` after setup — neither SP
// depends on the user's interactive login session.
type Config struct {
	TenantID       string `json:"tenant_id"`
	SubscriptionID string `json:"subscription_id"`

	// Manager SP — used by the broker to manage role assignments.
	ManagerClientID     string `json:"manager_client_id"`
	ManagerClientSecret string `json:"manager_client_secret"`

	// Worker SP — credentials handed to sessions, receives temporary roles.
	WorkerClientID     string `json:"worker_client_id"`
	WorkerClientSecret string `json:"worker_client_secret"`
	WorkerObjectID     string `json:"worker_object_id"`
}

// configPath returns the path to the Azure config file.
func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determining home directory: %w", err)
	}
	return filepath.Join(home, configDirName, configFileName), nil
}

// LoadConfig reads the Azure config from ~/.tiam/azure.json.
func LoadConfig() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("Azure not configured. Run: timebound-iam setup azure")
		}
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid Azure config in %s: %w. Run: timebound-iam setup azure", path, err)
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	if c.TenantID == "" {
		return fmt.Errorf("missing tenant_id")
	}
	if c.SubscriptionID == "" {
		return fmt.Errorf("missing subscription_id")
	}
	if c.ManagerClientID == "" {
		return fmt.Errorf("missing manager_client_id")
	}
	if c.ManagerClientSecret == "" {
		return fmt.Errorf("missing manager_client_secret")
	}
	if c.WorkerClientID == "" {
		return fmt.Errorf("missing worker_client_id")
	}
	if c.WorkerClientSecret == "" {
		return fmt.Errorf("missing worker_client_secret")
	}
	if c.WorkerObjectID == "" {
		return fmt.Errorf("missing worker_object_id")
	}
	return nil
}

// SaveConfig writes the Azure config to ~/.tiam/azure.json with 0600 permissions.
func SaveConfig(cfg *Config) error {
	path, err := configPath()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating config directory %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing config %s: %w", path, err)
	}

	return nil
}
