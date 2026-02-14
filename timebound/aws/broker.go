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

// NewBroker creates a Broker by loading AWS config and discovering the account ID.
func NewBroker(ctx context.Context) (*Broker, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
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

// LazyBroker defers broker initialization until the first GrantAccess call.
// This allows the MCP server to start even if AWS credentials aren't yet available.
type LazyBroker struct {
	mu     sync.Mutex
	broker *Broker
}

// NewLazyBroker creates a LazyBroker.
func NewLazyBroker() *LazyBroker {
	return &LazyBroker{}
}

func (lb *LazyBroker) init(ctx context.Context) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if lb.broker != nil {
		return nil
	}
	broker, err := NewBroker(ctx)
	if err != nil {
		return err
	}
	lb.broker = broker
	return nil
}

// GrantAccess initializes the broker on first call, then delegates.
func (lb *LazyBroker) GrantAccess(ctx context.Context, input GrantAccessInput) (*Session, error) {
	if err := lb.init(ctx); err != nil {
		return nil, fmt.Errorf("initializing AWS broker: %w", err)
	}
	return lb.broker.GrantAccess(ctx, input)
}
