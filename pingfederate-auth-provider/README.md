# PingFederate auth provider

Signs users in to Obot through Ping Identity PingFederate, using OpenID
Connect.

## Setting up PingFederate

1. Create an OAuth client for Obot (**Applications > OAuth > Clients**):
   - Client authentication: **client secret**.
   - Grant types: **Authorization Code** and **Refresh Token**.
   - Redirect URI: Obot's public URL with a trailing slash, for example
     `https://obot.example.com/`.
   - You can turn on **Require Proof Key for Code Exchange (PKCE)**.
   - OpenID Connect policy: release `sub`, `email`, `name` (or `given_name`
     and `family_name`), `preferred_username`, and, for group-based access, a
     group attribute (`groups` by default). Release groups in the **userinfo**
     response; groups released only in the ID token are not read.
   - PingFederate releases only the claims mapped to a scope the client
     requests, so map the groups attribute to a scope, such as `groups`, and
     add that scope to **Scopes** in Obot. Without it, users sign in with no
     groups.
2. In Obot, go to **Identity & Access > Auth Providers**, configure
   **PingFederate**, and enter the client ID, client secret, and issuer URL,
   such as `https://sso.example.com` or `https://sso.example.com:9031`. The
   issuer must match the `issuer` in `<issuer>/.well-known/openid-configuration`
   exactly, including the port and without a trailing slash.
3. If PingFederate's certificate is issued by a private CA, paste the CA chain
   into **CA Certificate (PEM)**, or set **CA Certificate File** to a path
   inside the Obot container. Obot's own trust store is not used for
   PingFederate.

PingFederate must be reached over HTTPS, and must sign ID tokens with an RSA,
RSA-PSS, ECDSA or EdDSA key.

## Users

- A user's identity is the `sub` claim, so it survives an email change.
- The email comes from the **Email Claim** (`email`). With the default claim, a
  user whose `email_verified` is `false` cannot sign in. If you use another
  claim, make sure users cannot edit that attribute themselves, or **Allowed
  E-Mail Domains** no longer restricts who signs in.
- The name shown in Obot comes from the **Name Claim** (`name`), falling back
  to `given_name` and `family_name`, then `preferred_username`, then the email.
- If a user's email changes in PingFederate, they are signed out of Obot within
  one **Token Refresh Duration**, and sign in again with the new email.

## Groups

Groups appear in Obot as `pingfederate/<group name>`, with the name exactly as
PingFederate sends it, for example
`pingfederate/cn=Admins,ou=Groups,dc=example,dc=com`. If PingFederate sends a
user's groups as one delimited string, set **Groups Delimiter**; leave it
empty for LDAP DNs, which contain commas.

- A change to a user's groups in PingFederate reaches Obot within one **Token
  Refresh Duration** (an hour by default), without the user signing in again.
- PingFederate cannot list its groups, so Obot's group picker shows the groups
  under **Known Groups**, one per line, plus every group a user has signed in
  with in the last 90 days. List the groups you want to give roles to under
  **Known Groups**, so you can do that before any member signs in.
- Requests made with Obot API keys use the groups the user had at their last
  browser sign-in or refresh.

With PostgreSQL, the provider keeps users' groups in Obot's database, in the
`pingfederate_user_groups` and `pingfederate_seen_groups` tables, so that every
Obot replica sees them. Obot drops these tables, with the provider's session
tables, when PingFederate is deconfigured. Without PostgreSQL, groups are kept
in memory, and each user's are recorded again at their next request after a
restart.

## When PingFederate is unavailable

Obot confirms each user's identity with PingFederate's userinfo endpoint. While
it is unreachable, users cannot sign in, and requests right after a session
refresh fail, until it is back. Other requests from signed-in users keep
working.

## Settings

| Setting | Variable | Default |
|---|---|---|
| Client ID | `OBOT_PINGFEDERATE_AUTH_PROVIDER_CLIENT_ID` | required |
| Client Secret | `OBOT_PINGFEDERATE_AUTH_PROVIDER_CLIENT_SECRET` | required |
| Issuer URL | `OBOT_PINGFEDERATE_AUTH_PROVIDER_ISSUER_URL` | required |
| Allowed E-Mail Domains | `OBOT_AUTH_PROVIDER_EMAIL_DOMAINS` | required; `*` for any |
| CA Certificate (PEM) | `OBOT_PINGFEDERATE_AUTH_PROVIDER_CA_CERTIFICATE` | none |
| CA Certificate File | `OBOT_PINGFEDERATE_AUTH_PROVIDER_CA_FILE` | none |
| Scopes | `OBOT_PINGFEDERATE_AUTH_PROVIDER_SCOPES` | `openid email profile` |
| Email Claim | `OBOT_PINGFEDERATE_AUTH_PROVIDER_EMAIL_CLAIM` | `email` |
| Name Claim | `OBOT_PINGFEDERATE_AUTH_PROVIDER_NAME_CLAIM` | `name` |
| Groups Claim | `OBOT_PINGFEDERATE_AUTH_PROVIDER_GROUPS_CLAIM` | `groups` |
| Groups Delimiter | `OBOT_PINGFEDERATE_AUTH_PROVIDER_GROUPS_DELIMITER` | none |
| Known Groups | `OBOT_PINGFEDERATE_AUTH_PROVIDER_KNOWN_GROUPS` | none |
| Userinfo Cache Duration | `OBOT_PINGFEDERATE_AUTH_PROVIDER_USERINFO_CACHE_TTL` | `5m` |
| Token Refresh Duration | `OBOT_AUTH_PROVIDER_TOKEN_REFRESH_DURATION` | `1h` |
| Enable Logging | `OBOT_AUTH_PROVIDER_ENABLE_LOGGING` | `false` |

## Development

```sh
go test ./...                                    # includes sign-ins against a mock identity provider
PINGFEDERATE_TEST_POSTGRES_DSN=... go test ./... # also runs the PostgreSQL tests
go run ./hack/mockidp                            # a mock identity provider for trying the provider in Obot
```

[`hack/pingfederate`](hack/pingfederate/README.md) runs a real PingFederate in
Docker, configured for Obot.
