package timebound

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/google/uuid"
)

const (
	brokerRoleName = "timebound-iam-broker"
	minTTL         = 15 * time.Minute
	maxTTL         = 12 * time.Hour
	// STS AssumeRole allows at most 12 managed policy ARNs per call.
	maxPolicyARNs = 12
)

// STSClient defines the STS operations needed by the Broker.
type STSClient interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
	AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

// CredentialGranter is the interface used by handlers to grant access.
type CredentialGranter interface {
	GrantAccess(ctx context.Context, input GrantAccessInput) (*Session, error)
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

// GrantAccessInput holds the parameters for granting temporary access.
type GrantAccessInput struct {
	Services []string
	Level    string
	TTL      time.Duration
	// Profile selects which AWS profile (and therefore which account) to
	// use. BrokerPool uses this to route to the correct Broker. Broker
	// itself does not use it for routing; it only stores it in the
	// Session for informational purposes.
	Profile string
}

// GrantAccess assumes the broker role with session policy ARNs scoped to the
// requested services and returns a Session with temporary credentials.
func (b *Broker) GrantAccess(ctx context.Context, input GrantAccessInput) (*Session, error) {
	if err := ValidateServices(input.Services); err != nil {
		return nil, err
	}

	if input.TTL < minTTL {
		return nil, fmt.Errorf("TTL must be at least %s", minTTL)
	}
	if input.TTL > maxTTL {
		return nil, fmt.Errorf("TTL must not exceed %s", maxTTL)
	}

	arns, err := GetPolicyARNs(input.Services, input.Level)
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

	sessionName := fmt.Sprintf("timebound-iam-%s", uuid.New().String())
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
	return &Session{
		ID:              sessionName,
		Services:        input.Services,
		Level:           input.Level,
		Profile:         input.Profile,
		AccessKeyID:     aws.ToString(creds.AccessKeyId),
		SecretAccessKey:  aws.ToString(creds.SecretAccessKey),
		SessionToken:    aws.ToString(creds.SessionToken),
		ExpiresAt:       aws.ToTime(creds.Expiration),
	}, nil
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

// GrantAccess looks up or creates a broker for the requested profile, then delegates.
func (bp *BrokerPool) GrantAccess(ctx context.Context, input GrantAccessInput) (*Session, error) {
	broker, err := bp.getOrCreate(ctx, input.Profile)
	if err != nil {
		return nil, fmt.Errorf("initializing AWS broker for profile %q: %w", input.Profile, err)
	}
	return broker.GrantAccess(ctx, input)
}
