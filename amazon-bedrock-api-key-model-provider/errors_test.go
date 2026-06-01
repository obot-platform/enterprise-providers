package main

import (
	"fmt"
	"testing"

	"github.com/aws/smithy-go"
)

func TestValidationErrorMessageForExpiredToken(t *testing.T) {
	err := fmt.Errorf("failed to validate AWS credentials: %w", &smithy.OperationError{
		ServiceID:     "Bedrock",
		OperationName: "ListFoundationModels",
		Err: &smithy.GenericAPIError{
			Code:    "AccessDeniedException",
			Message: "Bearer Token has expired",
		},
	})

	if got, want := validationErrorMessage(err), "Invalid Amazon Bedrock credentials: the bearer token has expired. Generate a new API key and try again."; got != want {
		t.Fatalf("validationErrorMessage() = %q, want %q", got, want)
	}
}

func TestValidationErrorMessageForAPIError(t *testing.T) {
	err := fmt.Errorf("failed to validate AWS credentials: %w", &smithy.GenericAPIError{
		Code:    "AccessDeniedException",
		Message: "User is not authorized to perform bedrock:ListFoundationModels",
	})

	if got, want := validationErrorMessage(err), "Invalid Amazon Bedrock credentials: access was denied. Check that the API key is valid, not expired, and configured for the selected region."; got != want {
		t.Fatalf("validationErrorMessage() = %q, want %q", got, want)
	}
}
