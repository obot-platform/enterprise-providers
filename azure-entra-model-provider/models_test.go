package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchDeploymentsFromManagement(t *testing.T) {
	tests := []struct {
		name       string
		response   managementDeploymentsResponse
		statusCode int
		wantErr    bool
		want       map[string]string
	}{
		{
			name: "single deployment",
			response: managementDeploymentsResponse{Value: []managementDeployment{
				{Name: "my-gpt4"},
			}},
			statusCode: 200,
			want:       map[string]string{"my-gpt4": "llm"},
		},
		{
			name: "usage type inferred from deployment name",
			response: managementDeploymentsResponse{Value: []managementDeployment{
				{Name: "text-embedding-ada-002"},
			}},
			statusCode: 200,
			want:       map[string]string{"text-embedding-ada-002": "text-embedding"},
		},
		{
			name: "two deployments of the same model",
			response: managementDeploymentsResponse{Value: []managementDeployment{
				{Name: "deploy-a"},
				{Name: "deploy-b"},
			}},
			statusCode: 200,
			want:       map[string]string{"deploy-a": "llm", "deploy-b": "llm"},
		},
		{
			name:       "non-200 response returns error",
			statusCode: 403,
			wantErr:    true,
		},
		{
			name:       "empty deployment list",
			statusCode: 200,
			want:       map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgmtServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.statusCode)
				_ = json.NewEncoder(w).Encode(tt.response)
			}))
			defer mgmtServer.Close()

			got, err := fetchDeploymentsFromManagementURL(context.Background(), mgmtServer.URL, "fake-token")
			if (err != nil) != tt.wantErr {
				t.Fatalf("fetchDeploymentsFromManagementURL() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d deployments, want %d: %v", len(got), len(tt.want), got)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("deployments[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}
