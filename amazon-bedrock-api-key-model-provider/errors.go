package main

import (
	"errors"
	"net/http"
	"strings"

	"github.com/obot-platform/enterprise-providers/amazon-bedrock-model-provider/bedrockcommon"
)

func validationErrorMessage(err error) string {
	if httpErr, ok := errors.AsType[bedrockcommon.HTTPError](err); ok {
		messageLower := strings.ToLower(httpErr.Body)
		if strings.Contains(messageLower, "token has expired") {
			return "Invalid Amazon Bedrock credentials: the bearer token has expired. Generate a new API key and try again."
		}
		switch {
		case strings.Contains(messageLower, "access denied"):
			fallthrough
		case strings.Contains(messageLower, "not authorized"):
			fallthrough
		case httpErr.StatusCode == http.StatusUnauthorized:
			fallthrough
		case httpErr.StatusCode == http.StatusForbidden:
			return "Invalid Amazon Bedrock credentials: access was denied. Check that the API key is valid, not expired, and configured for the selected region."
		}
		if httpErr.Body != "" {
			return "Invalid Amazon Bedrock credentials: " + httpErr.Body
		}
		return "Invalid Amazon Bedrock credentials: " + httpErr.Status
	}
	return "Invalid Amazon Bedrock credentials."
}
