package main

import (
	"fmt"
	"regexp"
	"strings"
)

// validUsageTypes is the set of recognized usage type values.
var validUsageTypes = map[string]struct{}{
	"llm":              {},
	"reasoning-llm":    {},
	"text-embedding":   {},
	"image-generation": {},
}

// parseDeployments parses a comma-separated list of deployment specs.
// Each spec is either "deploymentName" (defaults to usage type "llm") or
// "deploymentName:usageType". The resulting map is deploymentName->usageType.
func parseDeployments(s string) (map[string]string, error) {
	deployments := make(map[string]string)
	for spec := range strings.SplitSeq(s, ",") {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}

		parts := strings.SplitN(spec, ":", 2)
		switch len(parts) {
		case 1:
			if err := validateName(parts[0]); err != nil {
				return nil, fmt.Errorf("invalid deployment spec %q: %w", spec, err)
			}
			deployments[parts[0]] = "llm"
		case 2:
			deployment := strings.TrimSpace(parts[0])
			usageType := strings.TrimSpace(parts[1])
			if deployment == "" || usageType == "" {
				return nil, fmt.Errorf("invalid deployment spec %q: deployment name and usage type must be non-empty", spec)
			}
			if err := validateName(deployment); err != nil {
				return nil, fmt.Errorf("invalid deployment spec %q: %w", spec, err)
			}
			if _, ok := validUsageTypes[usageType]; !ok {
				return nil, fmt.Errorf("invalid deployment spec %q: usage type %q must be one of: llm, reasoning-llm, text-embedding, image-generation", spec, usageType)
			}
			deployments[deployment] = usageType
		}
	}
	if len(deployments) == 0 {
		return nil, fmt.Errorf("no valid deployments found in %q", s)
	}
	return deployments, nil
}

// validNameRe is an allowlist for Azure deployment names: alphanumeric, hyphens,
// underscores, and dots, starting with an alphanumeric character, max 64 characters.
var validNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9\-_.]{0,63}$`)

// validateName rejects deployment names that don't match the Azure naming allowlist.
func validateName(name string) error {
	if !validNameRe.MatchString(name) {
		return fmt.Errorf("name %q is invalid (must match [a-zA-Z0-9][a-zA-Z0-9\\-_.]{0,63})", name)
	}
	return nil
}
