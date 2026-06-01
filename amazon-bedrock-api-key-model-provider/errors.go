package main

import (
	"errors"
	"strings"

	"github.com/aws/smithy-go"
)

func validationErrorMessage(err error) string {
	if apiErr, ok := errors.AsType[smithy.APIError](err); ok {
		code := apiErr.ErrorCode()
		message := apiErr.ErrorMessage()
		if code == "AccessDeniedException" && strings.Contains(strings.ToLower(message), "token has expired") {
			return "Invalid Amazon Bedrock credentials: the bearer token has expired. Generate a new API key and try again."
		}
		if code == "AccessDeniedException" {
			return "Invalid Amazon Bedrock credentials: access was denied. Check that the API key is valid, not expired, and configured for the selected region."
		}
		if message != "" {
			return "Invalid Amazon Bedrock credentials: " + message
		}
		if code != "" {
			return "Invalid Amazon Bedrock credentials: " + code
		}
	}
	return "Invalid Amazon Bedrock credentials."
}
