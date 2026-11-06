#!/usr/bin/env python3
"""Configure the local PingFederate from compose.yaml for Obot.

Adds, through PingFederate's Admin API, what Ping's baseline profile lacks:

- the base URL, https://localhost:9031, which is also the issuer;
- an OpenID Connect policy, "obot", that looks the signed-in user up in
  PingDirectory and releases sub, email, name, given_name, family_name,
  preferred_username, and groups (isMemberOf, multi-valued); and
- a "groups" scope, because PingFederate releases only the claims mapped to
  a requested scope;
- an OAuth client, "obot", for the authorization code and refresh token
  grants, with a client secret and PKCE required.

The script is idempotent: it creates what is missing and replaces what
exists. It talks only to the local admin port, whose certificate is the
baseline profile's self-signed one, so it does not verify TLS.

Usage: python3 configure.py [--obot-url http://localhost:8080]
                            [--id-token-claims]
"""

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

ADMIN_API = "https://localhost:9999/pf-admin-api/v1"
ADMIN_USER = "administrator"
ADMIN_PASSWORD = "2FederateM0re"  # The baseline profile's documented default.

# Defined by Ping's baseline profile.
LDAP_DATA_STORE_ID = "LDAP-D803C87FAB2ADFB4B0A947B64BA6F0C6093A5CA3"
ACCESS_TOKEN_MANAGER_ID = "jwt"
USER_BASE_DN = "ou=people,dc=example,dc=com"

# The issuer. The baseline profile sets the base URL to the container's
# private hostname, which neither a browser nor Obot can reach.
BASE_URL = "https://localhost:9031"

POLICY_ID = "obot"
CLIENT_ID = "obot"
# A fixed secret for this local, throwaway PingFederate. Override it with
# PINGFEDERATE_CLIENT_SECRET.
DEFAULT_CLIENT_SECRET = "obot-local-test-secret"

# PingFederate releases only the claims mapped to a requested scope, so group
# membership gets a scope of its own, as administrators commonly set it up.
GROUPS_SCOPE = "groups"

LDAP_SOURCE_ID = "pingdirectoryuser"  # must be alphanumeric

# OIDC claim -> PingDirectory attribute. The subject is the access token's
# Username, which the baseline profile sets to the user's entryUUID: stable
# and opaque, like a production subject.
LDAP_CLAIMS = {
    "email": "mail",
    "name": "cn",
    "given_name": "givenName",
    "family_name": "sn",
    "preferred_username": "uid",
    "groups": "isMemberOf",
}


def request(method, path, body=None):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    auth = base64.b64encode(f"{ADMIN_USER}:{ADMIN_PASSWORD}".encode()).decode()
    req = urllib.request.Request(
        ADMIN_API + path,
        method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={
            "Authorization": "Basic " + auth,
            "X-XSRF-Header": "PingFederate",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, context=context) as resp:
            data = resp.read()
            return resp.status, json.loads(data) if data else None
    except urllib.error.HTTPError as e:
        data = e.read()
        try:
            return e.code, json.loads(data)
        except ValueError:
            return e.code, data.decode(errors="replace")


def upsert(collection, item_id, body):
    """PUT the resource if it exists, POST it otherwise."""
    status, _ = request("GET", f"{collection}/{item_id}")
    if status == 200:
        method, path = "PUT", f"{collection}/{item_id}"
    elif status == 404:
        method, path = "POST", collection
    else:
        sys.exit(f"GET {collection}/{item_id}: unexpected status {status}")
    status, result = request(method, path, body)
    if status not in (200, 201):
        sys.exit(f"{method} {path} failed with {status}:\n{json.dumps(result, indent=2)}")
    print(f"{'updated' if method == 'PUT' else 'created'} {collection}/{item_id}")
    return result


def set_base_url():
    status, settings = request("GET", "/serverSettings")
    if status != 200:
        sys.exit(f"GET /serverSettings failed with {status}: {settings}")
    if settings["federationInfo"].get("baseUrl") == BASE_URL:
        print(f"base URL is already {BASE_URL}")
        return
    settings["federationInfo"]["baseUrl"] = BASE_URL
    status, result = request("PUT", "/serverSettings", settings)
    if status != 200:
        sys.exit(f"PUT /serverSettings failed with {status}:\n{json.dumps(result, indent=2)}")
    print(f"set the base URL to {BASE_URL}")


def oidc_policy(id_token_claims):
    def attribute(name):
        return {
            "name": name,
            "multiValued": name == "groups",
            # PingFederate releases claims through userinfo by default; with
            # --id-token-claims they go in the ID token as well.
            "includeInIdToken": id_token_claims,
            "includeInUserInfo": True,
        }

    ldap_source = {"type": "LDAP_DATA_STORE", "id": LDAP_SOURCE_ID}
    return {
        "id": POLICY_ID,
        "name": "Obot",
        "accessTokenManagerRef": {"id": ACCESS_TOKEN_MANAGER_ID},
        "attributeContract": {
            "coreAttributes": [attribute("sub")],
            "extendedAttributes": [attribute(n) for n in LDAP_CLAIMS],
        },
        "attributeMapping": {
            "attributeSources": [
                {
                    "type": "LDAP",
                    "id": LDAP_SOURCE_ID,
                    "description": "The signed-in user in PingDirectory",
                    "dataStoreRef": {"id": LDAP_DATA_STORE_ID},
                    "baseDn": USER_BASE_DN,
                    "searchScope": "SUBTREE",
                    "searchFilter": "(entryUUID=${Username})",
                    "searchAttributes": sorted(set(LDAP_CLAIMS.values())),
                    "memberOfNestedGroup": False,
                    "attributeContractFulfillment": {},
                }
            ],
            "attributeContractFulfillment": {
                "sub": {"source": {"type": "TOKEN"}, "value": "Username"},
                **{claim: {"source": ldap_source, "value": attr} for claim, attr in LDAP_CLAIMS.items()},
            },
            "issuanceCriteria": {"conditionalCriteria": []},
        },
        "includeUserInfoInIdToken": id_token_claims,
        "returnIdTokenOnRefreshGrant": False,
        "scopeAttributeMappings": {
            "email": {"values": ["email"]},
            "profile": {"values": ["name", "given_name", "family_name", "preferred_username"]},
            GROUPS_SCOPE: {"values": ["groups"]},
        },
    }


def oauth_client(obot_url, secret):
    return {
        "clientId": CLIENT_ID,
        "name": "Obot",
        "enabled": True,
        # Obot receives the OAuth callback at its root.
        "redirectUris": [obot_url.rstrip("/") + "/"],
        "grantTypes": ["AUTHORIZATION_CODE", "REFRESH_TOKEN"],
        "clientAuth": {"type": "SECRET", "secret": secret},
        "requireProofKeyForCodeExchange": True,
        "bypassApprovalPage": True,
        "restrictScopes": False,
        "defaultAccessTokenManagerRef": {"id": ACCESS_TOKEN_MANAGER_ID},
        "oidcPolicy": {"policyGroup": {"id": POLICY_ID}},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--obot-url", default="http://localhost:8080", help="Obot's public URL (default: %(default)s)")
    parser.add_argument(
        "--id-token-claims",
        action="store_true",
        help="also put the claims in the ID token, not only in the userinfo response",
    )
    args = parser.parse_args()
    secret = os.environ.get("PINGFEDERATE_CLIENT_SECRET", DEFAULT_CLIENT_SECRET)

    status, version = request("GET", "/version")
    if status != 200:
        sys.exit(f"PingFederate's Admin API is not ready ({status}): {version}")
    print(f"PingFederate {version['version']}")

    set_base_url()
    upsert(
        "/oauth/authServerSettings/scopes/commonScopes",
        GROUPS_SCOPE,
        {"name": GROUPS_SCOPE, "description": "Group membership", "dynamic": False},
    )
    upsert("/oauth/openIdConnect/policies", POLICY_ID, oidc_policy(args.id_token_claims))
    upsert("/oauth/clients", CLIENT_ID, oauth_client(args.obot_url, secret))

    print()
    print("Configure the PingFederate auth provider in Obot with:")
    print(f"  Issuer URL:    {BASE_URL}")
    print(f"  Scopes:        openid email profile {GROUPS_SCOPE}")
    print(f"  Client ID:     {CLIENT_ID}")
    print(f"  Client Secret: {secret if 'PINGFEDERATE_CLIENT_SECRET' not in os.environ else '(from PINGFEDERATE_CLIENT_SECRET)'}")
    print("  CA Certificate: the output of ./ca.sh")
    print()
    print("Sign in as user.0 to user.9 (password 2FederateM0re).")


if __name__ == "__main__":
    main()
