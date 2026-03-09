package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/builder-magic/timebound-iam/timebound/core"
	"github.com/google/uuid"
	nanoid "github.com/matoous/go-nanoid/v2"
)

const (
	credKeyClientID       = "AZURE_CLIENT_ID"
	credKeyClientSecret   = "AZURE_CLIENT_SECRET"
	credKeyTenantID       = "AZURE_TENANT_ID"
	credKeySubscriptionID = "AZURE_SUBSCRIPTION_ID"

	metadataKeyAssignmentIDs = "role_assignment_ids"
)

// RoleAssignmentsClient defines the RBAC operations needed by the Broker.
type RoleAssignmentsClient interface {
	Create(ctx context.Context, scope string, roleAssignmentName string, parameters armauthorization.RoleAssignmentCreateParameters, options *armauthorization.RoleAssignmentsClientCreateOptions) (armauthorization.RoleAssignmentsClientCreateResponse, error)
	Delete(ctx context.Context, scope string, roleAssignmentName string, options *armauthorization.RoleAssignmentsClientDeleteOptions) (armauthorization.RoleAssignmentsClientDeleteResponse, error)
}

// Broker manages temporary Azure RBAC role assignments using a two-SP model:
//
//   - Manager SP: has "User Access Administrator" role, used server-side to
//     create and delete RBAC role assignments. Credentials never leave the server.
//   - Worker SP: starts with NO permissions, receives temporary role assignments.
//     Its credentials are returned to sessions.
//
// This means the user can `az logout` after setup — the broker authenticates
// as the manager SP, not the user.
type Broker struct {
	config     *Config
	authClient RoleAssignmentsClient
}

// NewBroker creates a Broker by loading the Azure config and authenticating
// as the manager service principal.
func NewBroker(ctx context.Context) (*Broker, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, err
	}

	cred, err := azidentity.NewClientSecretCredential(cfg.TenantID, cfg.ManagerClientID, cfg.ManagerClientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("creating manager SP credential: %w", err)
	}

	client, err := armauthorization.NewRoleAssignmentsClient(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("creating role assignments client: %w", err)
	}

	return &Broker{
		config:     cfg,
		authClient: client,
	}, nil
}

// NewBrokerWithClient creates a Broker with an injected client for testing.
func NewBrokerWithClient(cfg *Config, client RoleAssignmentsClient) *Broker {
	return &Broker{
		config:     cfg,
		authClient: client,
	}
}

// Name returns the provider name.
func (b *Broker) Name() string { return core.ProviderAzure }

// GrantAccess creates temporary RBAC role assignments for the worker SP
// and returns the worker SP credentials for the consumer to use.
func (b *Broker) GrantAccess(ctx context.Context, input core.GrantAccessInput) (*core.Session, error) {
	if input.TTL < core.MinTTL {
		return nil, fmt.Errorf("TTL must be at least %s", core.MinTTL)
	}
	if input.TTL > core.MaxTTL {
		return nil, fmt.Errorf("TTL must not exceed %s", core.MaxTTL)
	}

	var roleIDs []string
	var err error

	if len(input.ServiceScopes) > 0 {
		roleIDs, err = resolveScopedRoleIDs(input.ServiceScopes)
	} else {
		if err := ValidateServices(input.Services); err != nil {
			return nil, err
		}
		roleIDs, err = GetRoleDefinitionIDs(input.Services, input.Level)
	}
	if err != nil {
		return nil, fmt.Errorf("resolving role definitions: %w", err)
	}

	if len(roleIDs) == 0 {
		return nil, fmt.Errorf("at least one role definition is required")
	}

	id, err := nanoid.New(10)
	if err != nil {
		return nil, fmt.Errorf("generating session ID: %w", err)
	}

	scope := fmt.Sprintf("/subscriptions/%s", b.config.SubscriptionID)
	var assignmentNames []string

	for _, roleID := range roleIDs {
		assignmentName := uuid.New().String()
		roleDefID := fmt.Sprintf("%s/providers/Microsoft.Authorization/roleDefinitions/%s", scope, roleID)

		_, err := b.authClient.Create(ctx, scope, assignmentName, armauthorization.RoleAssignmentCreateParameters{
			Properties: &armauthorization.RoleAssignmentProperties{
				RoleDefinitionID: &roleDefID,
				PrincipalID:      &b.config.WorkerObjectID,
			},
		}, nil)
		if err != nil {
			// Clean up any assignments already created in this batch.
			b.cleanupAssignments(ctx, scope, assignmentNames)
			return nil, fmt.Errorf("creating role assignment for role %s: %w", roleID, err)
		}
		assignmentNames = append(assignmentNames, assignmentName)
	}

	return &core.Session{
		ID:       id,
		Provider: core.ProviderAzure,
		Services: input.Services,
		Level:    input.Level,
		Profile:  input.Profile,
		Credentials: map[string]string{
			credKeyClientID:       b.config.WorkerClientID,
			credKeyClientSecret:   b.config.WorkerClientSecret,
			credKeyTenantID:       b.config.TenantID,
			credKeySubscriptionID: b.config.SubscriptionID,
		},
		ExpiresAt: timeNow().Add(input.TTL),
		Metadata: map[string]string{
			metadataKeyAssignmentIDs: strings.Join(assignmentNames, ","),
		},
	}, nil
}

// ListServices returns all available Azure services.
func (b *Broker) ListServices() []core.ServiceInfo {
	return ListServices()
}

// Cleanup removes the RBAC role assignments created for a session.
func (b *Broker) Cleanup(ctx context.Context, session *core.Session) error {
	ids, ok := session.Metadata[metadataKeyAssignmentIDs]
	if !ok || ids == "" {
		return nil
	}

	scope := fmt.Sprintf("/subscriptions/%s", b.config.SubscriptionID)
	names := strings.Split(ids, ",")
	return b.cleanupAssignments(ctx, scope, names)
}

// cleanupAssignments deletes the given role assignments, collecting errors.
func (b *Broker) cleanupAssignments(ctx context.Context, scope string, names []string) error {
	var errs []string
	for _, name := range names {
		if name == "" {
			continue
		}
		_, err := b.authClient.Delete(ctx, scope, name, nil)
		if err != nil {
			errs = append(errs, fmt.Sprintf("deleting assignment %s: %v", name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// SubscriptionID returns the configured subscription ID.
func (b *Broker) SubscriptionID() string {
	return b.config.SubscriptionID
}

// TenantID returns the configured tenant ID.
func (b *Broker) TenantID() string {
	return b.config.TenantID
}
