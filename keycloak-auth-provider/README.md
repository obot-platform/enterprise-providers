# Keycloak authentication provider

Connect Keycloak to Obot so users can sign in with their existing accounts and
use Keycloak groups for access control. Use Keycloak 24 or later.

For setup instructions, see
[Obot's authentication provider guide](https://docs.obot.ai/configuration/auth-providers/#keycloak).

## Configuration

Create two clients in the same Keycloak realm: one for signing in to Obot and a
separate client with read-only access to users and groups. Enter their credentials
in **Identity & Access > Auth Providers > Keycloak**.

Leave **Admin URL** blank unless your Keycloak administrator provides a separate
address for the Admin API.

By default, users must have a verified email address in Keycloak to sign in.
If your organization does not verify email addresses, enable **Allow Unverified
Emails** in Obot. When allowing unverified emails, avoid granting owner or
administrator access automatically by email address through deployment settings.
Email-domain restrictions also depend on users having trustworthy email addresses.

**Token Refresh Duration** controls how often Obot refreshes authentication tokens
for active sessions. The default is 1 hour. Set it shorter than the realm's
**Access Token Lifespan**, under **Realm settings > Tokens**. Keycloak's default
lifespan is 5 minutes, so a value such as `4m` works. If tokens expire before Obot
refreshes them, updates to users' display names and avatars fail until the next
refresh.

## Users and groups

Obot uses Keycloak groups for access control. Users also inherit access granted
to parent groups. Disabled or deleted Keycloak users are denied access when Obot
next checks their account.

SCIM provisioning is not supported.
