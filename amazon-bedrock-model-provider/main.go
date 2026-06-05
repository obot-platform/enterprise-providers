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
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/obot-platform/enterprise-providers/amazon-bedrock-model-provider/bedrockcommon"
	bifrostprovider "github.com/obot-platform/enterprise-providers/bifrost-model-provider"
)

func main() {
	isValidate := len(os.Args) > 1 && os.Args[1] == "validate"
	if err := mainErr(context.Background(), isValidate); err != nil {
		if isValidate {
			message := validationErrorMessage(err)
			log.Printf("ERROR Invalid Amazon Bedrock Credentials: %v", err)
			errorJSON := map[string]string{"error": message}
			if encErr := json.NewEncoder(os.Stdout).Encode(errorJSON); encErr != nil {
				log.Fatal(encErr)
			}
			os.Exit(1)
		} else {
			log.Fatal(err)
		}
	}
}

func mainErr(ctx context.Context, isValidate bool) error {
	accessKeyID := os.Getenv("OBOT_AMAZON_BEDROCK_MODEL_PROVIDER_ACCESS_KEY_ID")
	if accessKeyID == "" {
		return errors.New("OBOT_AMAZON_BEDROCK_MODEL_PROVIDER_ACCESS_KEY_ID not found")
	}

	secretAccessKey := os.Getenv("OBOT_AMAZON_BEDROCK_MODEL_PROVIDER_SECRET_ACCESS_KEY")
	if secretAccessKey == "" {
		return errors.New("OBOT_AMAZON_BEDROCK_MODEL_PROVIDER_SECRET_ACCESS_KEY not found")
	}

	sessionToken := os.Getenv("OBOT_AMAZON_BEDROCK_MODEL_PROVIDER_SESSION_TOKEN")

	region := os.Getenv("OBOT_AMAZON_BEDROCK_MODEL_PROVIDER_REGION")
	if region == "" {
		region = "us-east-1"
	}

	keyConfig := &schemas.BedrockKeyConfig{
		AccessKey: schemas.EnvVar{Val: accessKeyID},
		SecretKey: schemas.EnvVar{Val: secretAccessKey},
		Region:    &schemas.EnvVar{Val: region},
	}
	if sessionToken != "" {
		keyConfig.SessionToken = &schemas.EnvVar{Val: sessionToken}
	}

	awsCfg := aws.Config{
		Region:      region,
		Credentials: credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, sessionToken),
	}
	bedrockClient := bedrock.NewFromConfig(awsCfg)

	// Validate credentials by making a lightweight API call.
	if _, err := bedrockClient.ListFoundationModels(ctx, &bedrock.ListFoundationModelsInput{}); err != nil {
		return fmt.Errorf("failed to validate AWS credentials: %w", err)
	}

	handler, err := bifrostprovider.NewHandler(ctx, bifrostprovider.NewAccount(schemas.Bedrock, []schemas.Key{{
		Models:           schemas.WhiteList{"*"},
		Weight:           1.0,
		BedrockKeyConfig: keyConfig,
	}}), "amazon-bedrock-model-provider")
	if err != nil {
		return fmt.Errorf("failed to initialize bifrost: %w", err)
	}
	defer handler.Shutdown()

	if isValidate {
		return nil
	}

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
