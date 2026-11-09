# PingFederate auth provider

An Obot authentication provider for Ping Identity PingFederate, using the
OpenID Connect authorization code flow.

Like Obot's other auth providers it is a thin wrapper around
[oauth2-proxy](https://github.com/obot-platform/oauth2-proxy), which owns the
login flow and the session cookie. This provider adds what Obot needs on top:
the endpoints Obot calls to identify the user behind a request, read their
profile, and list their groups.

## Setting up PingFederate

1. Create an OAuth client (**Applications > OAuth > Clients**) for Obot:
   - Client authentication: **client secret**.
   - Grant types: **Authorization Code** and **Refresh Token**.
   - Redirect URI: Obot's public URL with a trailing slash, for example
     `https://obot.example.com/`. Obot receives the callback at its root and
     forwards it to the provider; `/oauth2/callback` is not what PingFederate
     calls.
   - PKCE: the provider always sends an `S256` code challenge, so you can
     turn on **Require Proof Key for Code Exchange (PKCE)** for the client.
   - OpenID Connect policy: release `sub`, `email`, `name` (or `given_name`
     and `family_name`), `preferred_username`, and, for group-based access
     control in Obot, a group membership attribute (`groups` by default).
     Release groups in the userinfo response: the provider reads them only
     from userinfo, so a user whose groups are released only in the ID token
     is recorded with no groups. Releasing them in the ID token as well is
     harmless.
     PingFederate releases only the claims mapped to a scope the client
     requests, so map the groups attribute to a scope (for example a
     `groups` scope) and add that scope to **Scopes** in Obot. A user without
     it signs in with no groups.
2. In Obot, go to **Identity & Access > Auth Providers**, configure
   **PingFederate**, and enter the client ID, client secret, and issuer URL
   (`https://sso.example.com` or `https://sso.example.com:9031`). The issuer
   must match the `issuer` in `<issuer>/.well-known/openid-configuration`
   exactly, including the port and the absence of a trailing slash; the
   provider refuses to start otherwise and says what it found.
3. If PingFederate's TLS certificate is issued by a private CA, paste the CA
   certificate chain (PEM) into **CA Certificate**. The provider process does
   not inherit the Obot pod's trust store, so mounting a bundle on the pod is
   not enough on its own; alternatively point **CA Certificate File** at a
   path inside the container.

## How Obot identifies users

- The user's identity in Obot is the OIDC `sub` claim, which is stable even if
  the email address changes. Obot stores it as the provider user ID.
- The email address comes from the `email` claim (configurable). Logins are
  accepted when the ID token does not carry `email_verified`, which
  PingFederate typically omits. An explicit `email_verified: false` is
  rejected, because an unverified address would otherwise satisfy the allowed
  email domains. The check applies only when the email claim is `email`: with
  another **Email Claim**, make sure users cannot set that attribute
  themselves, or the allowed email domains no longer restrict who signs in.
- **Name Claim** chooses the claim shown in **Identity & Access → Users → Name**
  (default: `name`). If missing, the provider falls back to `name`, then
  `given_name` + `family_name`, then `preferred_username`, then the email.
  Release the name claim in userinfo or the ID token; userinfo takes precedence.
- Groups are reported to Obot as `pingfederate/<group name>`, matching the
  `groupIDPrefix` in the manifest. Group names are taken from the groups claim
  verbatim; set **Groups Delimiter** when PingFederate sends them as one
  delimited string.
- To map groups to Obot roles (**Identity & Access > Groups** in the admin UI,
  or `POST /api/group-role-assignments` with `groupName:
  "pingfederate/<group>"`), list the groups under **Known Groups** so the
  picker offers them before any member has signed in.

## How it works

Obot forwards the browser's `/oauth2/start`, `/oauth2/callback` and
`/oauth2/sign_out` requests to oauth2-proxy inside the provider, and calls
three provider-specific endpoints over the loopback interface:

| Endpoint | Purpose |
|---|---|
| `POST /obot-get-state` | Identifies the user behind a request from the session cookie, refreshing the upstream tokens when due. The response includes the user's groups, read from userinfo once per access token (see [Groups](#groups)). |
| `GET /obot-get-user-info` | Returns the profile for a bearer access token: the userinfo claims plus `id` (the subject), `name`, `email` and `picture`. Responses are cached per token for a few minutes because Obot asks often. If the userinfo endpoint is unavailable, the claims from the ID token are used. A userinfo answer without a subject, or for a different subject than the session's ID token, is an error. |
| `POST /obot-list-user-auth-groups` | Returns the groups recorded for a provider user ID. The provider records groups from every state and userinfo lookup. An unknown ID is an error rather than an empty list, which Obot would store, dropping the user's memberships. On an error Obot leaves its stored memberships alone, but fails the request that triggered the refresh with "Authentication provider configuration error", and retries a minute later (see "When Obot finds no record" under [Groups](#groups)). |
| `GET /obot-list-auth-groups` | Backs the group picker in Obot's admin UI. PingFederate has no directory API, so the provider lists the groups declared in **Known Groups** plus every group recorded at sign-in in the last 90 days. |
| `GET /obot-get-auth-groups` | Resolves group IDs to names; a group's name is its ID without the `pingfederate/` prefix. Obot sends each ID whole in a repeated `id` parameter. From an older Obot, which sends only `ids`, the IDs joined with commas, a piece that does not start with a provider prefix such as `pingfederate/` is read as the rest of the ID before it, which keeps an LDAP DN whole when that Obot sends it whole. Other providers' IDs are ignored. |

## Groups

PingFederate has no API for listing groups or a user's memberships, so the
provider learns groups from tokens and userinfo responses, and records them
for the lookups Obot makes without a token.

**Keeping groups current.** A session's ID token is the one it was created
with, and PingFederate does not issue a new one on refresh by default. So
groups come from userinfo, which evaluates the user's attributes when it is
asked: the provider asks it once per access token, and each refresh brings a
new token, so a change to a user's groups in PingFederate reaches Obot within
one **Token Refresh Duration**, without the user signing in again. Release the
groups attribute in userinfo. A userinfo answer without the groups claim means
the user has no groups, since PingFederate omits an empty attribute; groups
released only in the ID token are not read. (Only an identity provider without a
userinfo endpoint has its groups read from the ID token, ordered by its `iat`.)

A request that refreshes the session still carries the session from before the
refresh. The provider loads the refreshed session from the cookies the refresh
set, and records from that, so groups follow the refresh even for a client that
never sends the new cookies back.

Groups are recorded only from a successful userinfo answer for the session's
subject. If userinfo fails, nothing is recorded, and the user's existing record
stands. A user's groups are recorded under their subject only, the identifier
Obot looks them up by, never under an email address or another attribute a
user might share or choose.

**Where groups are recorded.** Every Obot replica runs its own copy of the
provider, so the records must be shared. When Obot uses PostgreSQL, which a
multi-replica deployment requires, the provider keeps them in Obot's database,
in two tables declared in the manifest's `postgresTables`:

| Table | Holds |
|---|---|
| `pingfederate_user_groups` | Each user's groups, under their subject. A record expires 24 hours after it was last written. |
| `pingfederate_seen_groups` | Every group recorded at sign-in, for the group picker. A group expires 90 days after it was last seen. |

The provider creates the tables when it starts, and only then: Obot drops them,
with the session tables, when the provider is deconfigured or a staged switch
to it is discarded, and a provider
still running on another replica must not bring them back. Expired rows are
deleted hourly.

Each record carries when its groups were observed: when userinfo answered.
Recording first reads, without locking, the user's recorded observation and
which of their groups were seen recently. Most requests repeat what is recorded,
and stop there. Only a newer observation, or one due for its hourly renewal,
goes on to a conditional upsert, which PostgreSQL applies only if the
observation is still newer than the recorded one, so a replica holding an older
answer cannot overwrite a newer one, whatever order the writes arrive in.
Reading first matters: an upsert locks the row it conflicts with even when it
changes nothing, and a group every user is in would have its row locked by
every request. Whether to write is decided by the database, not by anything a
replica remembers.

Without PostgreSQL, a single-replica installation, the provider keeps the same
records in memory. A restart forgets them, and each user's next request records
them again.

**When Obot finds no record.** Obot keeps its own copy of each user's group
memberships, and asks the provider for an update at most every 10 minutes per
user, only during browser requests. Each such request first asks the provider
for the session, which records the user's current groups, so Obot's lookup in
the same request normally finds them. It finds no record only when userinfo
fails on that request and the user has no current record: they have never been
recorded, their record expired (24 hours without a write), or the in-memory
store was restarted. Obot then leaves the memberships it has stored as they
are, but fails that request with a 500 "Authentication provider configuration
error", and skips lookups for that user for a minute, during which their
requests use the stored memberships. So a userinfo outage shows a user an
error about once a minute rather than changing their groups. Requests made
with Obot API keys never ask the provider: they use the stored memberships, as
of the user's last browser session.

**The group picker** lists **Known Groups** plus the groups recorded at
sign-in. List every group you intend to map to a role under **Known Groups**,
one per line (commas belong to the name, as in an LDAP DN),
so the picker offers it before any member has signed in.

## Security checks

PingFederate is a certified OpenID provider, so the provider applies the
standard OpenID Connect checks and none of them can be turned off: it reads
the discovery document, requires its `issuer` to match the configured issuer
URL, sends and verifies a nonce, uses `S256` PKCE, accepts ID tokens only for
the client ID, and rejects an explicit `email_verified: false`. The issuer and
the authorization, token, JWKS, and userinfo endpoints in the discovery
document must use HTTPS, except on a loopback host.

## Configuration

All settings are environment variables; Obot passes the values entered in the
admin UI. Required:

| Variable | Meaning |
|---|---|
| `OBOT_PINGFEDERATE_AUTH_PROVIDER_CLIENT_ID` | OAuth client ID |
| `OBOT_PINGFEDERATE_AUTH_PROVIDER_CLIENT_SECRET` | OAuth client secret |
| `OBOT_PINGFEDERATE_AUTH_PROVIDER_ISSUER_URL` | OpenID Connect issuer |
| `OBOT_AUTH_PROVIDER_COOKIE_SECRET` | Generated by Obot |
| `OBOT_AUTH_PROVIDER_EMAIL_DOMAINS` | Allowed email domains, `*` for any |

Optional (defaults in parentheses):

| Variable | Meaning |
|---|---|
| `OBOT_PINGFEDERATE_AUTH_PROVIDER_CA_CERTIFICATE` | PEM CA chain to trust for PingFederate |
| `OBOT_PINGFEDERATE_AUTH_PROVIDER_CA_FILE` | Path to a PEM CA bundle to trust |
| `OBOT_PINGFEDERATE_AUTH_PROVIDER_SCOPES` | Scopes to request (`openid email profile`); `openid` is always added |
| `OBOT_PINGFEDERATE_AUTH_PROVIDER_EMAIL_CLAIM` | Email claim (`email`) |
| `OBOT_PINGFEDERATE_AUTH_PROVIDER_NAME_CLAIM` | Name claim for the Users Name column (`name`) |
| `OBOT_PINGFEDERATE_AUTH_PROVIDER_GROUPS_CLAIM` | Groups claim (`groups`) |
| `OBOT_PINGFEDERATE_AUTH_PROVIDER_GROUPS_DELIMITER` | Delimiter when groups arrive as one string (none) |
| `OBOT_PINGFEDERATE_AUTH_PROVIDER_KNOWN_GROUPS` | Groups to list in Obot's group picker up front, one per line (none) |
| `OBOT_PINGFEDERATE_AUTH_PROVIDER_USERINFO_CACHE_TTL` | Profile cache lifetime (`5m`), `0` disables |
| `OBOT_AUTH_PROVIDER_TOKEN_REFRESH_DURATION` | Refresh upstream tokens after this age (`1h`) |
| `OBOT_AUTH_PROVIDER_ENABLE_LOGGING` | oauth2-proxy request and auth logging (`false`) |
| `OBOT_AUTH_PROVIDER_POSTGRES_*` | Session store settings, passed by Obot |

## Development

```sh
go test ./...                              # unit tests and an end-to-end login against a mock IdP
PINGFEDERATE_TEST_LOGGING=1 go test ./...  # same, with oauth2-proxy's own logs
go run ./hack/mockidp                      # a standalone mock IdP for trying the provider in Obot
```

[`hack/pingfederate`](hack/pingfederate/README.md) runs a real PingFederate,
backed by PingDirectory, in Docker, with the OAuth client and OIDC policy
Obot needs.

`internal/mockidp` is a small OpenID Connect provider used by the tests. It
serves discovery, JWKS, the authorization code flow with PKCE, refresh tokens
and userinfo, and signs in as a configurable user without a login page.
