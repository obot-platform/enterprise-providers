package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/aws/smithy-go/auth/bearer"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/obot-platform/enterprise-tools/amazon-bedrock-model-provider/bedrockcommon"
	bifrostprovider "github.com/obot-platform/enterprise-tools/bifrost-model-provider"
)

func main() {
	if err := mainErr(context.Background()); err != nil {
		log.Fatal(err)
	}
}

type tokenProvider struct {
	token string
}

func (t tokenProvider) RetrieveBearerToken(context.Context) (bearer.Token, error) {
	return bearer.Token{Value: t.token}, nil
}

func mainErr(ctx context.Context) error {
	apiKey := os.Getenv("OBOT_AMAZON_BEDROCK_API_KEY_MODEL_PROVIDER_API_KEY")
	if apiKey == "" {
		return errors.New("OBOT_AMAZON_BEDROCK_API_KEY_MODEL_PROVIDER_API_KEY not found")
	}

	region := os.Getenv("OBOT_AMAZON_BEDROCK_API_KEY_MODEL_PROVIDER_REGION")
	if region == "" {
		region = "us-east-1"
	}

	awsCfg := aws.Config{
		Region:                  region,
		BearerAuthTokenProvider: tokenProvider{token: apiKey},
	}
	bedrockClient := bedrock.NewFromConfig(awsCfg)

	handler, err := bifrostprovider.NewHandler(ctx, bifrostprovider.NewAccount(schemas.Bedrock, []schemas.Key{{
		Models: schemas.WhiteList{"*"},
		Weight: 1.0,
		Value:  schemas.EnvVar{Val: apiKey},
		BedrockKeyConfig: &schemas.BedrockKeyConfig{
			Region: &schemas.EnvVar{Val: region},
		},
	}}), "amazon-bedrock-api-key-model-provider")
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
		models, err := bedrockcommon.ListInferenceProfiles(r.Context(), bedrockClient)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to list models: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"data":   models,
		}); err != nil {
			log.Printf("Failed to encode models response: %v", err)
		}
	})

	mux.HandleFunc("POST /v1/responses", handler.HandleResponses)

	mux.HandleFunc("GET /validate", validate(bedrockClient))

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

func validate(bedrockClient *bedrock.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := bedrockClient.ListFoundationModels(r.Context(), &bedrock.ListFoundationModelsInput{}); err != nil {
			err = fmt.Errorf("failed to validate AWS credentials: %w", err)
			log.Printf("ERROR Invalid Amazon Bedrock Credentials: %v", err)
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
