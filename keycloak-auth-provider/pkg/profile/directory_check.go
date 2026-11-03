package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/obot-platform/enterprise-providers/keycloak-auth-provider/pkg/client"
)

// CheckDirectoryAccess reads one user and one group with the directory service account, so that wrong
// credentials or a missing view-users role are reported before the first sign-in needs them.
func CheckDirectoryAccess(ctx context.Context, directory *client.Client) error {
	for _, path := range []string{"/users", "/groups"} {
		var page []json.RawMessage
		status, err := read(ctx, directory, path, url.Values{"max": {"1"}, "briefRepresentation": {"true"}}, &page)
		var tokenErr *client.TokenError
		switch {
		case errors.As(err, &tokenErr):
			return fmt.Errorf("keycloak refused the directory service client's credentials (HTTP %d); check the Directory Service Client ID and Secret, and that the client has Service accounts roles enabled", tokenErr.Status)
		case err != nil:
			return err
		case status == http.StatusForbidden:
			return errors.New("the directory service account lacks the realm-management view-users role")
		case status == http.StatusNotFound:
			return fmt.Errorf("no Admin API at %s; check the Realm Issuer URL and Admin URL", directory.AdminURL())
		case status != http.StatusOK:
			return fmt.Errorf("directory read %s returned HTTP %d", path, status)
		}
	}
	return nil
}
