package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/obot-platform/enterprise-tools/azure-model-provider/azurecommon"
	bifrostprovider "github.com/obot-platform/enterprise-tools/bifrost-model-provider"
)

func main() {
	if err := mainErr(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func mainErr(ctx context.Context) error {
	endpoint := os.Getenv("OBOT_AZURE_MODEL_PROVIDER_ENDPOINT")
	if endpoint == "" {
		return errors.New("OBOT_AZURE_MODEL_PROVIDER_ENDPOINT not found")
	}
	endpoint = strings.TrimRight(endpoint, "/")
	if err := azurecommon.ValidateEndpoint(endpoint); err != nil {
		return fmt.Errorf("invalid OBOT_AZURE_MODEL_PROVIDER_ENDPOINT: %w", err)
	}

	apiKey := os.Getenv("OBOT_AZURE_MODEL_PROVIDER_API_KEY")
	if apiKey == "" {
		return errors.New("OBOT_AZURE_MODEL_PROVIDER_API_KEY not found")
	}

	apiVersion := os.Getenv("OBOT_AZURE_MODEL_PROVIDER_API_VERSION")
	if apiVersion == "" {
		apiVersion = "2025-01-01-preview"
	}

	deploymentsStr := os.Getenv("OBOT_AZURE_MODEL_PROVIDER_DEPLOYMENTS")
	if deploymentsStr == "" {
		return errors.New("OBOT_AZURE_MODEL_PROVIDER_DEPLOYMENTS not found")
	}
	deployments, err := parseDeployments(deploymentsStr)
	if err != nil {
		return fmt.Errorf("invalid OBOT_AZURE_MODEL_PROVIDER_DEPLOYMENTS: %w", err)
	}
	modelsResp, err := json.Marshal(map[string]any{
		"object": "list",
		"data":   azurecommon.BuildModelsFromDeployments(deployments),
	})
	if err != nil {
		return fmt.Errorf("failed to build models response: %w", err)
	}

	apiVersionEnvVar := schemas.EnvVar{Val: apiVersion}
	handler, err := bifrostprovider.NewHandler(ctx, bifrostprovider.NewAccount(schemas.Azure, []schemas.Key{{
		Models: schemas.WhiteList{"*"},
		Weight: 1.0,
		Value:  schemas.EnvVar{Val: apiKey},
		AzureKeyConfig: &schemas.AzureKeyConfig{
			Endpoint:   schemas.EnvVar{Val: endpoint},
			APIVersion: &apiVersionEnvVar,
		},
	}}), "azure-model-provider")
	if err != nil {
		return fmt.Errorf("failed to initialize bifrost: %w", err)
	}
	defer handler.Shutdown()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "http://127.0.0.1:%s", port)
	})

	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(modelsResp); err != nil {
			log.Printf("Failed to write models response: %v", err)
		}
	})

	mux.HandleFunc("POST /v1/responses", handler.HandleResponses)

	mux.HandleFunc("GET /validate", validate(endpoint, apiKey, apiVersion))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("404 %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	})

	listenHost := os.Getenv("OBOT_PROVIDER_LISTEN_HOST")
	if listenHost == "" {
		listenHost = "127.0.0.1"
	}

	addr := listenHost + ":" + port
	log.Printf("Starting server on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func validate(endpoint, apiKey, apiVersion string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := validateCredentials(r.Context(), endpoint, apiKey, apiVersion); err != nil {
			err = fmt.Errorf("failed to validate Azure credentials: %w", err)
			log.Printf("ERROR Invalid Azure Credentials: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if encErr := json.NewEncoder(w).Encode(map[string]string{"error": validationErrorMessage(err)}); encErr != nil {
				log.Printf("Failed to encode validation error response: %v", encErr)
			}
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

// validateCredentials checks that the API key is accepted by the Azure OpenAI endpoint.
func validateCredentials(ctx context.Context, endpoint, apiKey, apiVersion string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("failed to parse endpoint URL: %w", err)
	}
	u = u.JoinPath("/openai/models")
	q := u.Query()
	q.Set("api-version", apiVersion)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("api-key", apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return fmt.Errorf("Azure API returned %d (failed to read body: %v)", resp.StatusCode, err)
	}
	return parseAzureAPIError(resp.StatusCode, body)
}
