package dynamo

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// DeploymentRecord distinguishes an absent selector from an existing invalid
// one. InitializedVersion identifies an exact first deployment, allowing its
// later cumulative waves to be no-ops before LB status routes exist.
type DeploymentRecord struct {
	Version            string
	InitializedVersion string
}

// This bounds initialization's control-plane operations independently of the
// deploy command's convergence timeout (which may explicitly be zero).
const initializationRequestTimeout = 30 * time.Second

func (c *Client) GetDeploymentRecordConsistent(ctx context.Context, env, service, block string) (*DeploymentRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, initializationRequestTimeout)
	defer cancel()
	out, err := c.cl.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(deploymentBlocksTableName),
		ConsistentRead: aws.Bool(true),
		Key: map[string]types.AttributeValue{
			"env-service-block": &types.AttributeValueMemberS{Value: fmt.Sprintf("%s-%s-%s", env, service, block)},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to read deployment record: %w", err)
	}
	if out.Item == nil {
		return nil, nil
	}
	version, ok := out.Item["version"].(*types.AttributeValueMemberS)
	if !ok || version.Value == "" {
		return nil, fmt.Errorf("deployment record for block %q has no nonempty string version", block)
	}
	record := &DeploymentRecord{Version: version.Value}
	if attribute, exists := out.Item["initialized-version"]; exists {
		initialized, ok := attribute.(*types.AttributeValueMemberS)
		if !ok || initialized.Value == "" || initialized.Value != version.Value {
			return nil, fmt.Errorf("deployment record for block %q has an invalid initialization marker", block)
		}
		record.InitializedVersion = initialized.Value
	}
	return record, nil
}

// InitializeVersion is the sole mutation of the first-deployment path. There
// is no preceding mutable registry tag write: workers pull the versioned image
// from this selector. A competing selector always makes this creation fail.
// UpdateVersion replaces the complete item on an ordinary deployment, removing
// the initialization marker and restoring ordinary live-version checks.
func (c *Client) InitializeVersion(ctx context.Context, env, service, block, version string) error {
	if version == "" {
		return fmt.Errorf("initial deployment version must not be empty")
	}
	ctx, cancel := context.WithTimeout(ctx, initializationRequestTimeout)
	defer cancel()
	_, err := c.cl.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(deploymentBlocksTableName),
		Item: map[string]types.AttributeValue{
			"env-service-block":   &types.AttributeValueMemberS{Value: fmt.Sprintf("%s-%s-%s", env, service, block)},
			"version":             &types.AttributeValueMemberS{Value: version},
			"initialized-version": &types.AttributeValueMemberS{Value: version},
		},
		ConditionExpression: aws.String("attribute_not_exists(#key)"),
		ExpressionAttributeNames: map[string]string{
			"#key": "env-service-block",
		},
	})
	if err != nil {
		return fmt.Errorf("unable to initialize deployment record for block %q (no existing record may be replaced): %w", block, err)
	}
	return nil
}
