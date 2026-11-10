// Command mockidp serves the test identity provider for trying the provider
// in Obot without a real PingFederate:
//
//	go run ./hack/mockidp -listen 127.0.0.1:9400
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/obot-platform/enterprise-providers/pingfederate-auth-provider/internal/mockidp"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9400", "address to listen on")
	issuer := flag.String("issuer", "", "issuer URL (default http://<listen>)")
	clientID := flag.String("client-id", "obot", "OAuth client ID")
	clientSecret := flag.String("client-secret", "obot-secret", "OAuth client secret")
	subject := flag.String("sub", "sub-ada", "subject of the signed-in user")
	email := flag.String("email", "ada@example.com", "email of the signed-in user")
	name := flag.String("name", "Ada Lovelace", "display name of the signed-in user")
	groups := flag.String("groups", "admins,devs", "comma-separated groups of the signed-in user")
	groupsIn := flag.String("groups-in", "idtoken,userinfo", "where the groups claim appears: idtoken, userinfo, or both")
	pkce := flag.Bool("require-pkce", true, "reject authorization requests without PKCE")
	flag.Parse()

	if *issuer == "" {
		*issuer = "http://" + *listen
	}

	idp := mockidp.New(mockidp.Config{
		ClientID:            *clientID,
		ClientSecret:        *clientSecret,
		RequirePKCE:         *pkce,
		GroupsInIDToken:     strings.Contains(*groupsIn, "idtoken"),
		GroupsInUserinfo:    strings.Contains(*groupsIn, "userinfo"),
		EmailInIDToken:      true,
		AccessTokenLifetime: time.Hour,
	})
	idp.SetIssuer(*issuer)
	idp.SetUser(mockidp.User{
		Subject:           *subject,
		Email:             *email,
		Name:              *name,
		PreferredUsername: strings.SplitN(*email, "@", 2)[0],
		Picture:           "https://img.example.com/" + *subject + ".png",
		Groups:            strings.Split(*groups, ","),
	})

	fmt.Printf("mock identity provider\n  issuer:        %s\n  discovery:     %s%s\n  client id:     %s\n  client secret: %s\n  user:          %s <%s> groups=%s\n",
		*issuer, *issuer, mockidp.DiscoveryPath, *clientID, *clientSecret, *name, *email, *groups)

	// IPv4 only: WSL2's localhost forwarding, which Docker Desktop uses for
	// host.docker.internal, relays only IPv4 listeners.
	ln, err := net.Listen("tcp4", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mockidp: %v\n", err)
		os.Exit(1)
	}
	server := &http.Server{Handler: logRequests(idp), ReadHeaderTimeout: 10 * time.Second}
	if err := server.Serve(ln); err != nil {
		fmt.Fprintf(os.Stderr, "mockidp: %v\n", err)
		os.Exit(1)
	}
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s %s %s\n", time.Now().Format(time.TimeOnly), r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
