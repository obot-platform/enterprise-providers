# PingFederate authentication provider

Connect PingFederate to Obot so users can sign in with their existing accounts and
use the groups PingFederate releases for access control.

PingFederate has no API for listing groups, so this provider records the groups each
user has when they sign in, in tables it keeps in Obot's PostgreSQL database. It will
not start without the database.

For setup instructions, see
[Obot's authentication provider guide](https://docs.obot.ai/configuration/auth-providers/#pingfederate).

## PingFederate setup

The provider requests the `openid`, `profile`, and `email` scopes. PingFederate defines
only `openid` by default and rejects a sign-in that requests a scope it doesn't know, so
add `profile` and `email` as common scopes under **System > OAuth Settings > Scope
Management** if they aren't already defined.

Create an OAuth client for Obot under **Applications > OAuth > Clients**:

- **Client Authentication:** Client Secret.
- **Redirect URIs:** Obot's URL with a trailing slash, such as `https://obot.example.com/`.
- **Allowed Grant Types:** Authorization Code and Refresh Token.
- **Require Proof Key for Code Exchange (PKCE):** may be enabled. Obot always sends one.
- **Bypass Authorization Approval:** enable it, so that PingFederate doesn't ask users
  to approve Obot's access when they sign in.

The client's OpenID Connect policy must release these attributes:

| Attribute | Contents |
| --- | --- |
| `sub` | A stable, unique user ID, which Obot uses as the user's identity. |
| `email` | The user's email address. Required to sign in. |
| `name` | The display name. Without it, Obot uses `given_name` and `family_name`, then `preferred_username`. |
| `groups` | Optional. The user's groups, such as an LDAP `memberOf` attribute. Mark it **Multi-Valued**. |

Release `sub` and the name attributes in the userinfo response, which PingFederate does
by default (**Include in UserInfo**); Obot reads the display name from userinfo only.
`email` and `groups` may be released in the ID token, the userinfo response, or both.

Map `email` and `groups` from the same directory lookup (the same attribute source in
the policy). When PingFederate cannot reach that directory, it still answers, without
the attributes it would have read there. The provider recognizes a refreshed session
without an email as such a failure: it keeps the user's recorded groups and ends the
session, and the user signs in again once the directory is back. If `groups` came from
a different source than `email`, that source failing would go unnoticed, and users
would be removed from their groups until their next refresh after it recovers.

In the policy, enable **Return ID Token on Refresh Grant**. It is required: the groups
in a session come from its ID token, so a session that PingFederate refreshes without
a new one is ended, and the user signs in again.

Obot refreshes a session once it is older than **Token Refresh Duration** (default
`1h`). Keep that shorter than the **Token Lifetime** of the client's access token
manager, which defaults to 120 minutes: if access tokens expire before Obot refreshes
them, updates to users' display names fail until the next refresh. PingFederate's
refresh token rolling needs no change, because parallel refreshes of one session are
serialized.

## Configuration

Enter the client ID and secret, and PingFederate's base URL as the **Issuer URL**, in
**Identity & Access > Auth Providers > PingFederate**. The issuer URL must match the
`issuer` in `<issuer URL>/.well-known/openid-configuration` exactly, for example
`https://sso.example.com:9031`.

If PingFederate's TLS certificate is not issued by a public certificate authority,
paste the PEM of the CA that issued it into **CA Certificate**.

The provider trusts the `email` attribute as PingFederate releases it. It rejects an
address only when PingFederate marks it unverified (`email_verified` is `false`), and
PingFederate omits `email_verified` unless a policy releases it. **Allowed E-Mail
Domains** is therefore only as strong as the source of `email`: map it from an
attribute that users cannot change themselves.

## Users and groups

A group is shown by its value in the `groups` attribute, such as the LDAP DN
`cn=engineering,ou=groups,dc=example,dc=com`. Its ID in Obot, as used in filter and
guardrail conditions and policies, is `pingfederate/` followed by the value with `%`
written as `%25` and `,` as `%2C`:
`pingfederate/cn=engineering%2Cou=groups%2Cdc=example%2Cdc=com`.

Because the provider learns groups only from sign-ins, a group appears in Obot once
one of its members has signed in, and stops appearing once no recorded user is in it.
A user's groups are updated when they sign in and each time Obot refreshes their
tokens, as set by **Token Refresh Duration** (default `1h`). When a user has several
sessions, the groups from the most recently issued ID token are kept.

Removing a user from a group in PingFederate therefore takes effect in Obot only at
their next token refresh or sign-in, and a user who never signs in again keeps the
groups recorded at their last sign-in. There is no way to apply a group change
sooner; a shorter **Token Refresh Duration** shortens the delay. To withdraw what a
group grants before then, remove the group's role assignment in Obot, which affects
every member of the group.

SCIM provisioning is not supported.

## Development

The tests that use PostgreSQL run when `PINGFEDERATE_TEST_POSTGRES_DSN` is set, and
are skipped otherwise:

```sh
docker run -d --rm -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:17
PINGFEDERATE_TEST_POSTGRES_DSN='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' go test ./...
```
