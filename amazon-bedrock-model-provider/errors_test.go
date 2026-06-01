package main

import (
	"fmt"
	"testing"

	"github.com/aws/smithy-go"
)

func TestValidationErrorMessageForInvalidSecurityToken(t *testing.T) {
	err := fmt.Errorf("failed to validate AWS credentials: %w", &smithy.OperationError{
		ServiceID:     "Bedrock",
		OperationName: "ListFoundationModels",
		Err: &smithy.GenericAPIError{
			Code:    "UnrecognizedClientException",
			Message: "The security token included in the request is invalid.",
		},
	})

	if got, want := validationErrorMessage(err), "Invalid Amazon Bedrock credentials: the access key ID or session token is invalid. If these are temporary credentials, include a valid session token."; got != want {
		t.Fatalf("validationErrorMessage() = %q, want %q", got, want)
	}
}

func TestValidationErrorMessageForInvalidSignature(t *testing.T) {
	err := fmt.Errorf("failed to validate AWS credentials: %w", &smithy.OperationError{
		ServiceID:     "Bedrock",
		OperationName: "ListFoundationModels",
		Err: &smithy.GenericAPIError{
			Code:    "InvalidSignatureException",
			Message: "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.",
		},
	})

	if got, want := validationErrorMessage(err), "Invalid Amazon Bedrock credentials: the secret access key is invalid. Check the AWS secret access key and try again."; got != want {
		t.Fatalf("validationErrorMessage() = %q, want %q", got, want)
	}
}

func TestValidationErrorMessageForAccessDenied(t *testing.T) {
	err := fmt.Errorf("failed to validate AWS credentials: %w", &smithy.GenericAPIError{
		Code:    "AccessDeniedException",
		Message: "User is not authorized to perform bedrock:ListFoundationModels",
	})

	if got, want := validationErrorMessage(err), "Invalid Amazon Bedrock credentials: access was denied. Check that the credentials have Bedrock access and are configured for the selected region."; got != want {
		t.Fatalf("validationErrorMessage() = %q, want %q", got, want)
	}
}
