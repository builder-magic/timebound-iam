package cli

import (
	"fmt"
	"time"

	awsprovider "github.com/builder-magic/timebound-iam/timebound/aws"
	"github.com/builder-magic/timebound-iam/timebound/core"
)

// validateInputs checks service names and TTL bounds before the confirmation
// prompt so the user doesn't confirm only to hit a validation error.
func validateInputs(scopes []core.ServiceScope, ttl time.Duration) error {
	services := make([]string, len(scopes))
	for i, s := range scopes {
		services[i] = s.Service
	}
	if err := awsprovider.ValidateServices(services); err != nil {
		return err
	}

	if ttl < core.MinTTL {
		return fmt.Errorf("TTL must be at least %s", core.MinTTL)
	}
	if ttl > core.MaxTTL {
		return fmt.Errorf("TTL must not exceed %s", core.MaxTTL)
	}
	return nil
}
