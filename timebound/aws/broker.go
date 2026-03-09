package aws

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/builder-magic/timebound-iam/timebound/core"
	nanoid "github.com/matoous/go-nanoid/v2"
)

const (
	brokerRoleName = "timebound-iam-broker"
	// STS AssumeRole allows at most 12 managed policy ARNs per call.
	maxPolicyARNs = 12

	credKeyAccessKeyID     = "AWS_ACCESS_KEY_ID"
	credKeySecretAccessKey = "AWS_SECRET_ACCESS_KEY"
	credKeySessionToken    = "AWS_SESSION_TOKEN"
)

// STSClient defines the STS operations needed by the Broker.
type STSClient interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
	AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

// Broker handles STS AssumeRole calls against the timebound-iam-broker role.
type Broker struct {
	stsClient     STSClient
	accountID     string
	brokerRoleARN string
}

// NewBroker creates a Broker by loading the default AWS config.
func NewBroker(ctx context.Context) (*Broker, error) {
	return NewBrokerWithProfile(ctx, "")
}

// NewBrokerWithProfile creates a Broker using the given AWS profile.
// An empty profile uses the default credential chain.
func NewBrokerWithProfile(ctx context.Context, profile string) (*Broker, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	client := sts.NewFromConfig(cfg)
	return NewBrokerWithClient(ctx, client)
}

// NewBrokerWithClient creates a Broker using a provided STS client.
func NewBrokerWithClient(ctx context.Context, client STSClient) (*Broker, error) {
	identity, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("getting caller identity: %w", err)
	}

	accountID := aws.ToString(identity.Account)
	brokerARN := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, brokerRoleName)

	return &Broker{
		stsClient:     client,
		accountID:     accountID,
		brokerRoleARN: brokerARN,
	}, nil
}

// Name returns the provider name.
func (b *Broker) Name() string { return core.ProviderAWS }

// GrantAccess assumes the broker role with session policy ARNs scoped to the
// requested services and returns a Session with temporary credentials.
func (b *Broker) GrantAccess(ctx context.Context, input core.GrantAccessInput) (*core.Session, error) {
	if input.TTL < core.MinTTL {
		return nil, fmt.Errorf("TTL must be at least %s", core.MinTTL)
	}
	if input.TTL > core.MaxTTL {
		return nil, fmt.Errorf("TTL must not exceed %s", core.MaxTTL)
	}

	var arns []string
	var err error

	if len(input.ServiceScopes) > 0 {
		arns, err = resolveScopedARNs(input.ServiceScopes)
	} else {
		if err := ValidateServices(input.Services); err != nil {
			return nil, err
		}
		arns, err = GetPolicyARNs(input.Services, input.Level)
	}
	if err != nil {
		return nil, fmt.Errorf("resolving policy ARNs: %w", err)
	}

	policyARNs := make([]ststypes.PolicyDescriptorType, len(arns))
	for i, arn := range arns {
		policyARNs[i] = ststypes.PolicyDescriptorType{
			Arn: aws.String(arn),
		}
	}

	// Defense in depth: never call AssumeRole with zero PolicyArns. Without
	// session policies STS returns credentials with the broker role's full
	// permissions, bypassing all service scoping.
	if len(policyARNs) == 0 {
		return nil, fmt.Errorf("at least one policy ARN is required")
	}

	if len(policyARNs) > maxPolicyARNs {
		return nil, fmt.Errorf("too many services: STS allows at most %d session policies per call, got %d", maxPolicyARNs, len(policyARNs))
	}

	id, err := nanoid.New(10)
	if err != nil {
		return nil, fmt.Errorf("generating session ID: %w", err)
	}
	sessionName := fmt.Sprintf("timebound-iam-%s", id)
	durationSeconds := int32(input.TTL.Seconds())

	result, err := b.stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(b.brokerRoleARN),
		RoleSessionName: aws.String(sessionName),
		DurationSeconds: aws.Int32(durationSeconds),
		PolicyArns:      policyARNs,
	})
	if err != nil {
		return nil, fmt.Errorf("assuming broker role: %w", err)
	}

	creds := result.Credentials
	return &core.Session{
		ID:       id,
		Provider: core.ProviderAWS,
		Services: input.Services,
		Level:    input.Level,
		Profile:  input.Profile,
		Credentials: map[string]string{
			credKeyAccessKeyID:     aws.ToString(creds.AccessKeyId),
			credKeySecretAccessKey: aws.ToString(creds.SecretAccessKey),
			credKeySessionToken:    aws.ToString(creds.SessionToken),
		},
		ExpiresAt: aws.ToTime(creds.Expiration),
	}, nil
}

// ListServices returns all available AWS services sorted by name.
func (b *Broker) ListServices() []core.ServiceInfo {
	return ListServices()
}

// resolveScopedARNs resolves policy ARNs from per-service scopes,
// validating services and deduplicating ARNs.
func resolveScopedARNs(scopes []core.ServiceScope) ([]string, error) {
	services := make([]string, len(scopes))
	for i, s := range scopes {
		services[i] = s.Service
	}
	if err := ValidateServices(services); err != nil {
		return nil, err
	}

	seen := make(map[string]bool, len(scopes))
	arns := make([]string, 0, len(scopes))
	for _, s := range scopes {
		arn, err := GetPolicyARN(s.Service, s.Level)
		if err != nil {
			return nil, err
		}
		if seen[arn] {
			continue
		}
		seen[arn] = true
		arns = append(arns, arn)
	}
	return arns, nil
}

// AccountID returns the AWS account ID discovered during initialization.
func (b *Broker) AccountID() string {
	return b.accountID
}

// BrokerRoleARN returns the ARN of the broker role.
func (b *Broker) BrokerRoleARN() string {
	return b.brokerRoleARN
}

// BrokerFactory creates a Broker for the given profile.
type BrokerFactory func(ctx context.Context, profile string) (*Broker, error)

// brokerEntry holds a per-profile mutex so that broker creation for one
// profile does not block lookups or creation for other profiles.
type brokerEntry struct {
	mu     sync.Mutex
	broker *Broker
}

// BrokerPool manages a pool of Brokers keyed by AWS profile name.
// Brokers are lazily initialized on first use, allowing the MCP server
// to start even if AWS credentials aren't yet available.
type BrokerPool struct {
	mu      sync.Mutex
	entries map[string]*brokerEntry
	factory BrokerFactory
}

// NewBrokerPool creates a BrokerPool using the default broker factory.
func NewBrokerPool() *BrokerPool {
	return newBrokerPoolWithFactory(NewBrokerWithProfile)
}

// newBrokerPoolWithFactory creates a BrokerPool with an injectable factory for testing.
func newBrokerPoolWithFactory(factory BrokerFactory) *BrokerPool {
	return &BrokerPool{
		entries: make(map[string]*brokerEntry),
		factory: factory,
	}
}

// entryFor returns the entry for the given profile, creating one if needed.
// The global mutex is held only for the map operation.
func (bp *BrokerPool) entryFor(profile string) *brokerEntry {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	entry, ok := bp.entries[profile]
	if !ok {
		entry = &brokerEntry{}
		bp.entries[profile] = entry
	}
	return entry
}

func (bp *BrokerPool) getOrCreate(ctx context.Context, profile string) (*Broker, error) {
	entry := bp.entryFor(profile)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.broker != nil {
		return entry.broker, nil
	}

	broker, err := bp.factory(ctx, profile)
	if err != nil {
		return nil, err
	}
	entry.broker = broker
	return broker, nil
}

// Name returns the provider name.
func (bp *BrokerPool) Name() string { return core.ProviderAWS }

// GrantAccess looks up or creates a broker for the requested profile, then delegates.
func (bp *BrokerPool) GrantAccess(ctx context.Context, input core.GrantAccessInput) (*core.Session, error) {
	broker, err := bp.getOrCreate(ctx, input.Profile)
	if err != nil {
		return nil, fmt.Errorf("initializing AWS broker for profile %q: %w", input.Profile, err)
	}
	return broker.GrantAccess(ctx, input)
}

// ListServices returns all available AWS services.
func (bp *BrokerPool) ListServices() []core.ServiceInfo {
	return ListServices()
}
