# A local PingFederate for testing

`compose.yaml` runs PingFederate 13.1 backed by PingDirectory, from Ping's
`baseline` server profiles. `configure.py` then adds what Obot needs through
PingFederate's Admin API. Use it to try the provider, or a change to it,
against the real product.

Both images are multi-architecture (amd64 and arm64).

## License

The containers fetch a 30-day Ping Identity DevOps evaluation license when
they first start, which only works with images published in the last 90
days. Register for the DevOps program to get a user name and key (see
[Ping's DevOps registration](https://developer.pingidentity.com/devops/how-to/devopsRegistration.html)),
and export them in the shell that runs `docker compose up`:

```sh
export PING_IDENTITY_DEVOPS_USER=...   # the email you registered
export PING_IDENTITY_DEVOPS_KEY=...
```

`compose.yaml` names these variables but never holds their values. Do not
write them into it or into an env file.

## Start it

```sh
docker compose pull
docker compose up -d
# Wait until both containers are healthy (several minutes on first start):
docker compose ps
# Once, after the first start; see "Known issues":
docker compose restart pingfederate
python3 configure.py            # --obot-url if Obot is not on http://localhost:8080
./ca.sh > /tmp/pingfederate-ca.pem
```

`configure.py` is safe to re-run. It sets:

- the **base URL**, and so the issuer, to `https://localhost:9031`. The
  baseline profile uses the container's private hostname, which neither a
  browser nor Obot can reach;
- a **`groups` scope**. PingFederate releases only the claims mapped to a
  scope the client requests, so group membership needs a scope of its own;
- an **OIDC policy**, `obot`, that looks the user up in PingDirectory and
  releases `sub`, `email`, `name`, `given_name`, `family_name`,
  `preferred_username` and `groups` (the user's `isMemberOf`, multi-valued).
  Claims go in the userinfo response, PingFederate's default; pass
  `--id-token-claims` to put them in the ID token as well; and
- an **OAuth client**, `obot`, for the authorization code and refresh token
  grants, with client secret `obot-local-test-secret` (override it with
  `PINGFEDERATE_CLIENT_SECRET`), PKCE required, and redirect URI
  `http://localhost:8080/`.

## Configure Obot

Start Obot with authentication on and this repository as its provider
registry, after `make build` here:

```sh
OBOT_SERVER_ENABLE_AUTHENTICATION=true \
OBOT_SERVER_PROVIDER_REGISTRIES=/path/to/providers \
make dev
```

In **Identity & Access > Auth Providers**, configure **PingFederate** with:

| Setting | Value |
|---|---|
| Client ID | `obot` |
| Client Secret | `obot-local-test-secret` |
| Issuer URL | `https://localhost:9031` |
| CA Certificate (PEM) | the contents of `/tmp/pingfederate-ca.pem` |
| Scopes | `openid email profile groups` |

Sign in as `user.0` to `user.9`, password `2FederateM0re`. The PingFederate
admin console is at <https://localhost:9999/pingfederate/app>
(`administrator` / `2FederateM0re`).

What a user looks like to Obot:

- `sub` is the user's PingDirectory `entryUUID`, which the baseline profile
  carries in the access token as `Username`.
- The display name is the user's `cn`, for example "Raeann Brooke" for
  `user.0`.
- Groups are the full DNs from `isMemberOf`, for example
  `pingfederate/cn=group.0,ou=Groups,dc=example,dc=com`. The DNs contain
  commas, so leave **Groups Delimiter** empty.
- Refresh responses carry no new ID token, PingFederate's default.

To change a user's groups, use PingDirectory's tools, for example:

```sh
docker compose exec -T pingdirectory ldapmodify --hostname localhost --port 1636 \
  --useSSL --trustAll --bindDN cn=administrator --bindPassword 2FederateM0re <<'EOF'
dn: cn=group.0,ou=groups,dc=example,dc=com
changetype: modify
add: member
member: uid=user.1,ou=people,dc=example,dc=com
EOF
```

## Known issues

- On the first start, PingFederate imports the baseline configuration while
  its PingDirectory connection is still loading, and its OAuth grant store
  stays undefined until PingFederate restarts. Without the restart, the token
  endpoint answers `server_error` and `server.log` says "The Access Grant
  Management data store is not defined."
- The containers fetch the server profiles from the `master` branch of
  [pingidentity-server-profiles](https://github.com/pingidentity/pingidentity-server-profiles)
  at first start, so a change there can change this environment.

## Clean up

```sh
docker compose down -v
```
