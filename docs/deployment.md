# Deployment

Configuration and deployment details for the celine-policies stack.

## Docker Compose Stack

The `docker-compose.yaml` defines the full development stack:

| Service | Image | Port | Description |
|---------|-------|------|-------------|
| `keycloak` | Custom (from `keycloak/Dockerfile`) | 8080 | Identity provider with `rec` login and email themes |
| `keycloak-sync` | Same as `mqtt_auth` | — | Runs `bootstrap` + `sync` on startup, then exits |
| `sync-users` | Same as `mqtt_auth` | — | Imports example REC users, then exits |
| `mqtt_auth` | From `./Dockerfile` | 8009 | MQTT auth HTTP backend |
| `provisioning` | Same as `mqtt_auth` | 8010, **not published** | The only writer of participant accounts |
| `mosquitto` | `ghcr.io/lhns/mosquitto-go-auth:3.3.0-mosquitto_2.0.22` | 1883, 1884 | MQTT broker (TCP + WebSocket) |
| `redis` | `redis:7.2-alpine` | — | Cache backend |
| `oauth2-proxy` | `quay.io/oauth2-proxy/oauth2-proxy:v7.11.0` | 4180 | OAuth2 reverse proxy |
| `mailpit` | `axllent/mailpit:v1.31.1` | 1025 (SMTP), 8025 (UI) | Keycloak's outgoing mail in dev: kept, not delivered |

### Startup Order

1. **keycloak** starts first (health check on port 9000)
2. **keycloak-sync** runs bootstrap + sync, then exits
3. **sync-users** imports example users, then exits
4. **mqtt_auth** starts after keycloak-sync and sync-users complete
5. **provisioning** starts after keycloak-sync completes — it authenticates as
   `svc-provisioning`, a client `sync` creates, so it cannot bootstrap the realm it
   authenticates against
6. **mosquitto** starts after redis is up and mqtt_auth is healthy

### The provisioning service has no published port, and that is the guard

`provisioning` is declared with `expose` and not `ports`. It holds realm-wide Keycloak
administration, and the whole argument for that grant being acceptable is that nothing
outside the network reaches it — see
[ADR-0007](decisions/ADR-0007-realm-wide-administration-is-declared-for-a-holder-with-no-public-route.md).

**Publishing the port, or adding a route to it in the ingress, converts `manage-realm` into
an internet-facing credential.** It would still check scopes on the token, because it
authorises by `provisioning.*` like every other service — but that is defence in depth, not
the control, and it is not what the grant was justified by. The corresponding guard lives
in `../celine-dev`'s Caddyfile, where somebody adding a route will read it.

## Email: invitations and password recovery

**Keycloak sends every email**; the provisioning service only asks it to, through
`execute-actions-email`. The templates are the `rec` email theme
(`keycloak/themes/rec/email/`, `it`, `en` and `es`), and no password is ever generated or
put into an email. What each route sends is in the
[API reference](api-reference.md#provisioning-service).

### What a realm needs, and who owns it

| Setting | Owner | Notes |
|---|---|---|
| `internationalizationEnabled: true`, `supportedLocales: [it, en, es]`, `defaultLocale: it` | `keycloak bootstrap` (planned, not built yet) | **Must be on before the provisioning service writes `locale`**: without it Keycloak answers `201` and drops the value |
| `emailTheme: rec`, `resetPasswordAllowed: true`, `actionTokenGeneratedByAdminLifespan: 604800`, `actionTokenGeneratedByUserLifespan: 3600` | `keycloak bootstrap` (planned, not built yet) | Until then, set by hand on each realm |
| `smtpServer` | infra, and only infra, outside dev | A credential. The realm template reaches new realms only; an existing realm gets it once, by hand. The local dev import points it at `mailpit` (requester, 2026-09-14) |

`bootstrap` does not own these yet: that waits on `bootstrap` gaining its platform
settings. **Until it does, an operator sets them on each realm**, for example with `kcadm`:

```bash
kcadm.sh update realms/celine \
  -s internationalizationEnabled=true -s 'supportedLocales=["it","en","es"]' -s defaultLocale=it \
  -s emailTheme=rec -s resetPasswordAllowed=true \
  -s actionTokenGeneratedByAdminLifespan=604800 -s actionTokenGeneratedByUserLifespan=3600
```

`verifyEmail` is deliberately **not** set: the invitation already carries `VERIFY_EMAIL`,
and turning it on would stop every existing account with `emailVerified: false` at its next
sign-in. `passwordPolicy` stays at Keycloak's default.

### Locally

`mailpit` keeps every message in its UI at <http://localhost:8025> and delivers none.
The dev import (`config/keycloak/import/realm-celine.json`) points `smtpServer` at
`mailpit:1025`, which reaches **a realm created from it only** — `--import-realm` skips a
realm that already exists. On an existing local realm, set it once:

```bash
kcadm.sh update realms/celine -s 'smtpServer.host=mailpit' -s 'smtpServer.port=1025' \
  -s 'smtpServer.from=noreply@celine.localhost' -s 'smtpServer.fromDisplayName=CELINE'
```

Other workspace services can send through it too: SMTP is published on the host's 1025, so
a container uses `172.17.0.1:1025` (the same host-gateway convention as the registry URL) and
a process on the host uses `localhost:1025`.

To let real mail reach a few addresses, set both `EMAIL_DEV_RECIPIENTS` (comma-separated) and
`MAILPIT_RELAY_HOST` (with `MAILPIT_RELAY_PORT`, `_USERNAME`, `_PASSWORD` as needed). Mailpit
then relays only those addresses, through an anchored, escaped match built by
`config/mailpit/start.sh`, and the provisioning service invites only those addresses.
Everyone else gets a `WARNING` in the service log and `invitation: not_on_dev_list`. An
account with no email address is `no_email` in every mode, not `not_on_dev_list`.

Outside dev, set `CELINE_PROVISIONING_EMAIL_MODE=deliver` and
`CELINE_PROVISIONING_INVITE_REDIRECT_URI` to the webapp root.

## Dockerfile

The MQTT auth service image (`Dockerfile`) is a multi-stage build:

1. **Builder** — installs `uv`, syncs dependencies, installs the package
2. **Runtime** — copies `.venv`, `src/`, `policies/`, and `clients.yaml`; runs as non-root user (`app:1000`)

```
EXPOSE 8009
CMD ["uvicorn", "celine.mqtt_auth.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8009"]
```

## Configuration Reference

### MQTT Auth Service

Environment variables with `CELINE_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `CELINE_OIDC_*` | (from celine-sdk) | OIDC/JWT validation |
| `CELINE_POLICIES_DIR` | `./policies` | Rego policy directory |
| `CELINE_POLICIES_DATA_DIR` | `None` | Policy data JSON directory |
| `CELINE_POLICIES_CACHE_ENABLED` | `true` | Decision cache on/off |
| `CELINE_POLICIES_CACHE_TTL` | `300` | Cache TTL (seconds) |
| `CELINE_POLICIES_CACHE_MAXSIZE` | `10000` | Max cached decisions |
| `CELINE_MQTT_POLICY_PACKAGE` | `celine.mqtt.acl` | Rego package for ACL |
| `CELINE_MQTT_SUPERUSER_SCOPE` | `mqtt.admin` | Superuser scope name |
| `CELINE_LOG_LEVEL` | `INFO` | Log level |

### Keycloak CLI

Environment variables with `CELINE_KEYCLOAK_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `CELINE_KEYCLOAK_BASE_URL` | `http://keycloak.celine.localhost` | Keycloak URL |
| `CELINE_KEYCLOAK_REALM` | `celine` | Target realm. Outranks `realm:` in `clients.yaml`, and is outranked by `--realm` |
| `CELINE_KEYCLOAK_ADMIN_USER` | — | Admin username |
| `CELINE_KEYCLOAK_ADMIN_PASSWORD` | — | Admin password |
| `CELINE_KEYCLOAK_ADMIN_CLIENT_ID` | `celine-admin-cli` | Service client ID |
| `CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET` | — | Service client secret |
| `CELINE_KEYCLOAK_SECRETS_FILE` | `.client.secrets.yaml` | Secrets file path |

### Sync Users

Environment variables with `CELINE_SYNC_USERS_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `CELINE_SYNC_USERS_REC_YAML` | — | Path to REC YAML |
| `CELINE_SYNC_USERS_GROUPS` | (empty) | Space-separated group paths |
| `CELINE_SYNC_USERS_TEMP_PASSWORD` | (random) | Fixed password for all users |
| `CELINE_SYNC_USERS_TEMPORARY` | `true` | Force password reset on first login |
| `CELINE_SYNC_USERS_DRY_RUN` | `false` | Preview mode |
| `CELINE_SYNC_USERS_REGISTRY_URL` | — | rec-registry base URL. Setting it selects the live registry instead of a file |
| `CELINE_SYNC_USERS_REGISTRY_CLIENT_ID` | `celine-cli` | Keycloak client the registry is read as |
| `CELINE_SYNC_USERS_REGISTRY_CLIENT_SECRET` | — | Its secret. Falls back to that client's entry in the secrets file |
| `CELINE_SYNC_USERS_COMMUNITIES` | (empty) | Space-separated community keys. Empty → every community |

#### Which source a run reconciles

A **file** is a picture of the community at export time, so a run against one
leaves out everybody `onboarding` has approved since it was taken. A run against
the **registry** reconciles what is true. Both are supported and neither is
deprecated: bootstrap runs before the registry holds anything, and an offline run
is a real case.

```bash
# the file path, unchanged
celine-policies keycloak sync-users greenland.yaml

# the live registry, every community it holds
celine-policies keycloak sync-users --from-registry \
  --registry-url http://api.celine.localhost/rec-registry

# one community, and report divergence without writing anything
celine-policies keycloak sync-users --from-registry \
  --registry-url http://api.celine.localhost/rec-registry \
  --community gr-renewable-community --check
```

Passing both a path and `--from-registry` is refused rather than resolved.

`--check` writes nothing and exits non-zero when a member of the source has no
Keycloak account, is outside their REC organization, or is outside a group
`clients.yaml` declares under `admin_permissions`. It exists because none of
those is visible to a health probe: the failure they produce is a person who logs
in and cannot see their own community.

**Only `active` members are provisioned.** The registry keys a member `pending`
before approval and `suspended` or `inactive` after withdrawal; those are skipped
with a log line. A member carrying no `status` at all is treated as active, which
is what keeps hand-authored seed files working. Nothing is ever disabled —
skipping provisioning and revoking access are different acts.

The registry client needs `rec-registry.export`. The default, `celine-cli`, holds
`rec-registry.admin`, which is wider than that: see
[ADR-0006](decisions/ADR-0006-the-registry-is-the-source-of-members.md) for why,
and what to change to narrow it.

### Keycloak

The Keycloak service uses the custom image from `keycloak/Dockerfile` (KC 26.7.3 + rec theme). Key environment variables:

| Variable | Value | Description |
|----------|-------|-------------|
| `KC_DB` | `dev-file` | Dev-mode file-based DB |
| `KC_BOOTSTRAP_ADMIN_USERNAME` | `admin` | Initial admin username |
| `KC_BOOTSTRAP_ADMIN_PASSWORD` | `admin` | Initial admin password |
| `KC_HOSTNAME` | `keycloak.celine.localhost` | Public hostname |
| `KC_HTTP_PORT` | `8080` | HTTP port |

A realm import file at `config/keycloak/import/realm-celine.json` seeds the `celine` realm on first startup.

### Mosquitto

Configuration at `config/mosquitto/mosquitto.conf`. Key settings:

- JWT backend via mosquitto-go-auth, pointing to `host.docker.internal:8009`
- Listeners on port 1883 (MQTT) and 1884 (WebSocket)
- Redis caching available but disabled by default
- Superuser check disabled (`auth_opt_disable_superuser true`)
- Anonymous access disabled

### OAuth2 Proxy

Configuration at `config/oauth2-proxy/oauth2-proxy.cfg`. Runs on port 4180.

## Keycloak Custom Image

The `keycloak/` directory builds a custom Keycloak image:

- Base: `quay.io/keycloak/keycloak:26.7.3`
- Adds the `rec` login and email themes (see [`keycloak/README.md`](../keycloak/README.md))
- Pre-builds Keycloak at image build time for faster startup
- Version tracked in `keycloak/version.txt` (`26.7.3-1.1.0`)

A GitHub Actions workflow (`.github/workflows/build-keycloak.yaml`) detects changes to `keycloak/version.txt` and publishes an updated image.

## CI/CD

### Workflows

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `release.yaml` | Push to main / tags | Release Docker images |
| `build-keycloak.yaml` | Changes to `keycloak/version.txt` | Build and publish custom Keycloak image |

### Semantic Release

The project uses `python-semantic-release` for versioning:

```bash
task release
# Runs: uv run semantic-release version --no-vcs-release && git push && git push --tags
```

Commit messages follow conventional commits (`feat:`, `fix:`, `chore:`).

## Skaffold

A `skaffold.yaml` is available for Kubernetes development workflows.
