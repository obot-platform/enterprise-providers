// Package bifrostprovider contains shared HTTP handler logic for Bifrost-based model providers.
package bifrostprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
)

// Model is a simplified OpenAI-compatible model representation.
type Model struct {
	ID       string            `json:"id"`
	Object   string            `json:"object"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Handler wraps a Bifrost client and provider, exposing http.HandlerFunc-compatible methods.
type Handler struct {
	client   *bifrost.Bifrost
	provider schemas.ModelProvider
	logger   schemas.Logger
}

// NewHandler initializes a Bifrost client from the given Account and returns a Handler.
// It creates a logger for the supplied providerName and uses it to initialize the client.
// Call Shutdown when the handler is no longer needed.
func NewHandler(ctx context.Context, account *Account, providerName string) (*Handler, error) {
	if account == nil {
		return nil, errors.New("account must not be nil")
	}
	logger := NewSlogLogger(providerName)
	client, err := bifrost.Init(ctx, schemas.BifrostConfig{
		Account: account,
		Logger:  logger,
	})
	if err != nil {
		return nil, err
	}
	return &Handler{client: client, provider: account.provider, logger: logger}, nil
}

// Shutdown releases resources held by the underlying Bifrost client.
func (h *Handler) Shutdown() {
	h.client.Shutdown()
}

// ListModels returns the list of models available from the configured provider.
func (h *Handler) ListModels(ctx context.Context) ([]Model, error) {
	bifrostCtx := schemas.NewBifrostContext(ctx, schemas.NoDeadline)
	resp, bifrostErr := h.client.ListModelsRequest(bifrostCtx, &schemas.BifrostListModelsRequest{
		Provider: h.provider,
	})
	if bifrostErr != nil {
		return nil, errors.New(bifrost.GetErrorMessage(bifrostErr))
	}

	models := make([]Model, 0, len(resp.Data))
	for _, m := range resp.Data {
		models = append(models, Model{
			ID:     m.ID,
			Object: "model",
		})
	}
	return models, nil
}

// HandleResponses decodes a BifrostResponsesRequest, executes it via streaming SSE,
// and writes back the response.
func (h *Handler) HandleResponses(w http.ResponseWriter, r *http.Request) {
	var bifrostReq schemas.BifrostResponsesRequest
	if err := json.NewDecoder(r.Body).Decode(&bifrostReq); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	h.logger.Debug("incoming responses request", "model", bifrostReq.Model, "request_provider", bifrostReq.Provider)
	bifrostReq.Provider = h.provider

	bifrostCtx := schemas.NewBifrostContext(r.Context(), schemas.NoDeadline)
	h.handleStreamingResponses(bifrostCtx, w, &bifrostReq)
}

func (h *Handler) handleStreamingResponses(ctx *schemas.BifrostContext, w http.ResponseWriter, req *schemas.BifrostResponsesRequest) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	stream, bifrostErr := h.client.ResponsesStreamRequest(ctx, req)
	if bifrostErr != nil {
		http.Error(w, bifrost.GetErrorMessage(bifrostErr), http.StatusInternalServerError)
		return
	}

	for chunk := range stream {
		if chunk.BifrostError != nil {
			errMsg := bifrost.GetErrorMessage(chunk.BifrostError)
			h.logger.Error("bifrost stream error", "err", errMsg)
			fmt.Fprintf(w, "data: {\"error\": %q}\n\n", errMsg)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			return
		}

		if chunk.BifrostResponsesStreamResponse == nil {
			continue
		}

		data, err := json.Marshal(chunk.BifrostResponsesStreamResponse)
		if err != nil {
			h.logger.Error("bifrost: error marshaling stream chunk", "err", err)
			continue
		}

		fmt.Fprintf(w, "data: %s\n\n", data)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}

	fmt.Fprintf(w, "data: [DONE]\n\n")
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}
