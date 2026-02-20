package cli

import (
	"fmt"
	"time"

	timebound "github.com/builder-magic/timebound-iam/timebound/aws"
)

// validateInputs checks service names and TTL bounds before the confirmation
// prompt so the user doesn't confirm only to hit a validation error.
func validateInputs(scopes []timebound.ServiceScope, ttl time.Duration) error {
	services := make([]string, len(scopes))
	for i, s := range scopes {
		services[i] = s.Service
	}
	if err := timebound.ValidateServices(services); err != nil {
		return err
	}

	if ttl < timebound.MinTTL {
		return fmt.Errorf("TTL must be at least %s", timebound.MinTTL)
	}
	if ttl > timebound.MaxTTL {
		return fmt.Errorf("TTL must not exceed %s", timebound.MaxTTL)
	}
	return nil
}
