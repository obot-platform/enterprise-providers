package main

import (
	"errors"
	"strings"

	"github.com/aws/smithy-go"
)

func validationErrorMessage(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		message := apiErr.ErrorMessage()
		messageLower := strings.ToLower(message)

		switch {
		case code == "UnrecognizedClientException" && strings.Contains(messageLower, "security token"):
			return "Invalid Amazon Bedrock credentials: the access key ID or session token is invalid. If these are temporary credentials, include a valid session token."
		case code == "InvalidSignatureException":
			return "Invalid Amazon Bedrock credentials: the secret access key is invalid. Check the AWS secret access key and try again."
		case code == "AccessDeniedException":
			return "Invalid Amazon Bedrock credentials: access was denied. Check that the credentials have Bedrock access and are configured for the selected region."
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
