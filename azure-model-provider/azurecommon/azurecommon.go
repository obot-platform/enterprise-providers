package azurecommon

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	bifrostprovider "github.com/obot-platform/enterprise-providers/bifrost-model-provider"
)

// azureEndpointSuffixes is an allowlist of recognized Azure OpenAI endpoint host suffixes.
var azureEndpointSuffixes = []string{
	".openai.azure.com",
	".cognitiveservices.azure.com",
	".services.ai.azure.com",
	".models.ai.azure.com",
}

// ValidateEndpoint enforces HTTPS, an empty query/fragment, and an allowlisted Azure OpenAI host.
func ValidateEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("endpoint must use HTTPS")
	}
	if u.User != nil {
		return errors.New("endpoint must not contain user info")
	}
	if u.RawQuery != "" {
		return errors.New("endpoint must not contain a query string")
	}
	if u.Fragment != "" {
		return errors.New("endpoint must not contain a fragment")
	}
	host := strings.ToLower(u.Hostname())
	for _, suffix := range azureEndpointSuffixes {
		if strings.HasSuffix(host, suffix) {
			return nil
		}
	}
	return fmt.Errorf("host %q is not a recognized Azure OpenAI endpoint (must end in .openai.azure.com, .cognitiveservices.azure.com, .services.ai.azure.com, or .models.ai.azure.com)", host)
}

// DeploymentUsageType infers usage type from a deployment name.
// Used by the Entra provider where deployments are auto-discovered and usage type cannot be specified explicitly.
func DeploymentUsageType(name string) string {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "embed") {
		return "text-embedding"
	}
	if strings.Contains(lower, "dall-e") || strings.Contains(lower, "image") {
		return "image-generation"
	}
	return "llm"
}

// BuildModelsFromDeployments converts a deploymentName->usageType map into a list
// of OpenAI-compatible model objects.
func BuildModelsFromDeployments(deployments map[string]string) []bifrostprovider.Model {
	models := make([]bifrostprovider.Model, 0, len(deployments))
	for deploymentName, usageType := range deployments {
		models = append(models, bifrostprovider.Model{
			ID:     deploymentName,
			Object: "model",
			Metadata: map[string]string{
				"usage": usageType,
			},
		})
	}
	return models
}
