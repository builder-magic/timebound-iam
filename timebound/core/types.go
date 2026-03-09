package core

import (
	"context"
	"time"
)

const (
	ProviderAWS   = "aws"
	ProviderAzure = "azure"

	LevelReadOnly = "read_only"
	LevelFull     = "full"

	// MinTTL is the minimum allowed credential duration.
	MinTTL = 15 * time.Minute
	// MaxTTL is the maximum allowed credential duration.
	MaxTTL = 12 * time.Hour
)

// ServiceScope pairs a service name with an access level, allowing
// per-service granularity (e.g. s3:read_only + dynamodb:full).
type ServiceScope struct {
	Service string
	Level   string
}

// ServiceInfo describes an available service and its supported access levels.
type ServiceInfo struct {
	Name   string   `json:"name"`
	Levels []string `json:"levels"`
}

// GrantAccessInput holds the parameters for granting temporary access.
type GrantAccessInput struct {
	Services []string
	Level    string
	TTL      time.Duration
	// Profile selects which credential profile to use. For AWS this is
	// the AWS profile name; for Azure it can be a subscription alias.
	Profile       string
	ServiceScopes []ServiceScope
}

// Session represents an active set of temporary cloud credentials.
type Session struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	// Services lists the cloud services granted access to.
	Services []string `json:"services"`
	Level    string   `json:"level"`
	Profile  string   `json:"profile,omitempty"`
	// Credentials holds provider-specific environment variable key-value pairs.
	// For AWS: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN.
	// For Azure: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID.
	Credentials map[string]string `json:"-"`
	ExpiresAt   time.Time         `json:"expires_at"`
	// Metadata holds provider-specific data needed for cleanup
	// (e.g. Azure role assignment IDs).
	Metadata map[string]string `json:"metadata,omitempty"`
}

// IsExpired reports whether the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// CredentialGranter grants temporary, scoped cloud credentials.
type CredentialGranter interface {
	GrantAccess(ctx context.Context, input GrantAccessInput) (*Session, error)
}

// SessionCleaner performs provider-specific cleanup when a session expires.
// AWS does not need this (STS credentials expire automatically). Azure
// uses it to delete RBAC role assignments.
type SessionCleaner interface {
	Cleanup(ctx context.Context, session *Session) error
}

// ServiceLister returns the services available for a provider.
type ServiceLister interface {
	ListServices() []ServiceInfo
}

// Provider combines credential granting and service listing.
type Provider interface {
	CredentialGranter
	ServiceLister
	Name() string
}
