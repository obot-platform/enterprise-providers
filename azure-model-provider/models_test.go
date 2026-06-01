package main

import (
	"testing"

	"github.com/obot-platform/enterprise-tools/azure-model-provider/azurecommon"
)

func TestParseDeployments(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    map[string]string
		wantErr bool
	}{
		{
			name:  "simple deployment name defaults to llm",
			input: "gpt-4",
			want:  map[string]string{"gpt-4": "llm"},
		},
		{
			name:  "deployment with explicit usage type",
			input: "my-embed:text-embedding",
			want:  map[string]string{"my-embed": "text-embedding"},
		},
		{
			name:  "reasoning-llm usage type",
			input: "my-o3:reasoning-llm",
			want:  map[string]string{"my-o3": "reasoning-llm"},
		},
		{
			name:  "image-generation usage type",
			input: "my-dalle:image-generation",
			want:  map[string]string{"my-dalle": "image-generation"},
		},
		{
			name:  "two deployments of the same model",
			input: "gpt-4.1-mini,gpt-4.1-mini-2",
			want:  map[string]string{"gpt-4.1-mini": "llm", "gpt-4.1-mini-2": "llm"},
		},
		{
			name:  "multiple mixed specs",
			input: "gpt-4,my-embed:text-embedding",
			want:  map[string]string{"gpt-4": "llm", "my-embed": "text-embedding"},
		},
		{
			name:  "whitespace trimmed",
			input: " gpt-4 , gpt-3.5-turbo ",
			want:  map[string]string{"gpt-4": "llm", "gpt-3.5-turbo": "llm"},
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "empty deployment name",
			input:   ":text-embedding",
			wantErr: true,
		},
		{
			name:    "empty usage type",
			input:   "my-deploy:",
			wantErr: true,
		},
		{
			name:    "invalid usage type",
			input:   "my-deploy:unknown",
			wantErr: true,
		},
		{
			name:    "path traversal in deployment name",
			input:   "../etc/passwd",
			wantErr: true,
		},
		{
			name:    "slash in deployment name",
			input:   "my/deployment:llm",
			wantErr: true,
		},
		{
			name:  "skips empty comma-separated entries",
			input: "gpt-4,,gpt-3.5-turbo",
			want:  map[string]string{"gpt-4": "llm", "gpt-3.5-turbo": "llm"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDeployments(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDeployments(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("parseDeployments(%q) len = %d, want %d", tt.input, len(got), len(tt.want))
					return
				}
				for k, v := range tt.want {
					if got[k] != v {
						t.Errorf("parseDeployments(%q)[%q] = %q, want %q", tt.input, k, got[k], v)
					}
				}
			}
		})
	}
}

func TestDeploymentUsageType(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"gpt-4", "llm"},
		{"gpt-3.5-turbo", "llm"},
		{"text-embedding-ada-002", "text-embedding"},
		{"my-embed-model", "text-embedding"},
		{"dall-e-3", "image-generation"},
		{"image-generator", "image-generation"},
		{"DALL-E-3", "image-generation"},
		{"TEXT-EMBEDDING-ADA", "text-embedding"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := azurecommon.DeploymentUsageType(tt.name)
			if got != tt.want {
				t.Errorf("deploymentUsageType(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}
