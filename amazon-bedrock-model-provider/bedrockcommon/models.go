package bedrockcommon

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/aws/aws-sdk-go-v2/service/bedrock/types"
	bifrostprovider "github.com/obot-platform/enterprise-tools/bifrost-model-provider"
)

// ListInferenceProfiles returns all active system-defined Bedrock inference profiles.
// We call the AWS SDK directly rather than using bifrost's ListModels because bifrost
// returns foundation model IDs (e.g. "anthropic.claude-3-5-sonnet-20241022-v2:0") that
// require a "us." cross-region inference prefix to be routable. The AWS
// ListInferenceProfiles API returns the correct prefixed IDs directly, and also lets us
// determine usage type from the underlying foundation model's output modalities.
func ListInferenceProfiles(ctx context.Context, client *bedrock.Client) ([]bifrostprovider.Model, error) {
	usageByModelID, err := buildModelUsageMap(ctx, client)
	if err != nil {
		return nil, err
	}

	var models []bifrostprovider.Model
	var nextToken *string
	for {
		resp, err := client.ListInferenceProfiles(ctx, &bedrock.ListInferenceProfilesInput{
			TypeEquals: types.InferenceProfileTypeSystemDefined,
			NextToken:  nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list inference profiles: %w", err)
		}
		for _, p := range resp.InferenceProfileSummaries {
			if p.Status != types.InferenceProfileStatusActive || p.InferenceProfileId == nil {
				continue
			}
			usage := inferenceProfileUsage(p, usageByModelID)
			if usage == "" {
				continue
			}
			models = append(models, bifrostprovider.Model{
				ID:     *p.InferenceProfileId,
				Object: "model",
				Metadata: map[string]string{
					"usage": usage,
				},
			})
		}
		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}
	return models, nil
}

// buildModelUsageMap calls ListFoundationModels and returns a map of model ID → usage type.
// Legacy models are excluded so their inference profiles get filtered out — they return
// "endpoint not found" or "access denied (legacy)" errors on invocation even though
// ListInferenceProfiles still reports their profiles as ACTIVE.
func buildModelUsageMap(ctx context.Context, client *bedrock.Client) (map[string]string, error) {
	resp, err := client.ListFoundationModels(ctx, &bedrock.ListFoundationModelsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list foundation models: %w", err)
	}
	usageMap := make(map[string]string, len(resp.ModelSummaries))
	for _, m := range resp.ModelSummaries {
		if m.ModelId == nil {
			continue
		}
		if m.ModelLifecycle != nil && m.ModelLifecycle.Status == types.FoundationModelLifecycleStatusLegacy {
			continue
		}
		usageMap[*m.ModelId] = modalitiesToUsage(m.OutputModalities)
	}
	return usageMap, nil
}

// inferenceProfileUsage resolves the usage type for a profile by looking up the
// underlying foundation model's output modalities. Returns "" if unknown.
func inferenceProfileUsage(p types.InferenceProfileSummary, usageByModelID map[string]string) string {
	for _, m := range p.Models {
		if m.ModelArn == nil {
			continue
		}
		modelID := modelIDFromARN(*m.ModelArn)
		if usage, ok := usageByModelID[modelID]; ok {
			return usage
		}
	}
	return ""
}

// modalitiesToUsage maps Bedrock output modalities to an Obot usage type string.
func modalitiesToUsage(modalities []types.ModelModality) string {
	for _, mod := range modalities {
		switch mod {
		case types.ModelModalityEmbedding:
			return "text-embedding"
		case types.ModelModalityImage:
			return "image-generation"
		}
	}
	return "llm"
}

// modelIDFromARN extracts the model ID from a Bedrock foundation model ARN.
// Format: arn:aws:bedrock:{region}::foundation-model/{modelId}
func modelIDFromARN(arn string) string {
	if idx := strings.LastIndex(arn, "/"); idx >= 0 {
		return arn[idx+1:]
	}
	return arn
}
