package bedrockcommon

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock/types"
)

func TestModelIDFromARN(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-express-v1",
			want:  "amazon.titan-text-express-v1",
		},
		{
			input: "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-20241022-v2:0",
			want:  "anthropic.claude-3-5-sonnet-20241022-v2:0",
		},
		{
			input: "no-slash",
			want:  "no-slash",
		},
		{
			input: "trailing/",
			want:  "",
		},
		{
			input: "trailing///",
			want:  "",
		},
		{
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := modelIDFromARN(tt.input)
			if got != tt.want {
				t.Errorf("modelIDFromARN(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestModalitiesToUsage(t *testing.T) {
	tests := []struct {
		name       string
		modalities []types.ModelModality
		want       string
	}{
		{
			name:       "no modalities defaults to llm",
			modalities: nil,
			want:       "llm",
		},
		{
			name:       "text modality defaults to llm",
			modalities: []types.ModelModality{types.ModelModalityText},
			want:       "llm",
		},
		{
			name:       "embedding modality",
			modalities: []types.ModelModality{types.ModelModalityEmbedding},
			want:       "text-embedding",
		},
		{
			name:       "image modality",
			modalities: []types.ModelModality{types.ModelModalityImage},
			want:       "image-generation",
		},
		{
			name:       "embedding takes priority over text",
			modalities: []types.ModelModality{types.ModelModalityText, types.ModelModalityEmbedding},
			want:       "text-embedding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := modalitiesToUsage(tt.modalities)
			if got != tt.want {
				t.Errorf("modalitiesToUsage(%v) = %q, want %q", tt.modalities, got, tt.want)
			}
		})
	}
}

func TestInferenceProfileUsage(t *testing.T) {
	usageMap := map[string]string{
		"anthropic.claude-3-5-sonnet-v2": "llm",
		"amazon.titan-embed-text-v1":     "text-embedding",
	}

	tests := []struct {
		name    string
		profile types.InferenceProfileSummary
		want    string
	}{
		{
			name: "resolves usage from model ARN",
			profile: types.InferenceProfileSummary{
				Models: []types.InferenceProfileModel{
					{ModelArn: aws.String("arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-v2")},
				},
			},
			want: "llm",
		},
		{
			name: "resolves embedding usage",
			profile: types.InferenceProfileSummary{
				Models: []types.InferenceProfileModel{
					{ModelArn: aws.String("arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-embed-text-v1")},
				},
			},
			want: "text-embedding",
		},
		{
			name: "returns empty for unknown model",
			profile: types.InferenceProfileSummary{
				Models: []types.InferenceProfileModel{
					{ModelArn: aws.String("arn:aws:bedrock:us-east-1::foundation-model/unknown.model")},
				},
			},
			want: "",
		},
		{
			name: "skips nil ARN entries",
			profile: types.InferenceProfileSummary{
				Models: []types.InferenceProfileModel{
					{ModelArn: nil},
					{ModelArn: aws.String("arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-v2")},
				},
			},
			want: "llm",
		},
		{
			name: "no models returns empty",
			profile: types.InferenceProfileSummary{
				Models: nil,
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferenceProfileUsage(tt.profile, usageMap)
			if got != tt.want {
				t.Errorf("inferenceProfileUsage() = %q, want %q", got, tt.want)
			}
		})
	}
}
