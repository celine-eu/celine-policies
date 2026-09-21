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
2. **keycloak-sync** runs bootstrap (the platform level, from the mounted `platform.yaml`) + sync, then exits.
   A sync that runs on every start and may be handed an incomplete file set can pass
   `--additive`: it adds and updates, removes nothing, and lists what it held back
   (README, "Adding without removing"). A declared removal then needs a plain `sync`.
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

Every setting below is **platform level**, and `keycloak bootstrap` is its only writer. It
reaches existing realms on every run, which the realm imports never do (`--import-realm` and
infra's `IGNORE_EXISTING` skip a realm that already exists).

| Setting | Declared in | Notes |
|---|---|---|
| `internationalizationEnabled: true`, `supportedLocales: [it, en, es]`, `defaultLocale: it` | [`platform.yaml`](../platform.yaml) | **Must be on before the provisioning service writes `locale`**: without it Keycloak answers `201` and drops the value. So `bootstrap` runs before the new provisioning image reaches a realm |
| `emailTheme: rec`, `loginTheme: rec`, `resetPasswordAllowed: true`, `actionTokenGeneratedByAdminLifespan: 604800`, `actionTokenGeneratedByUserLifespan: 3600` | `platform.yaml` | `bootstrap` refuses a theme the server does not list: Keycloak itself accepts any name and silently sends its own emails |
| token and session lifespans, `organizationsEnabled`, `adminPermissionsEnabled`, the role groups, brute-force tuning | `platform.yaml` | `sync-orgs` and `sync-users` refuse a realm without Organizations; `sync` refuses to grant `admin_permissions` without fine-grained admin permissions |
| `bruteForceProtected` | `CELINE_KEYCLOAK_BRUTE_FORCE_ENABLED` | Unset: on, and off when `ENV` is `dev`, `development`, `local`, `test` or `ci` |
| `smtpServer` | `CELINE_KEYCLOAK_SMTP_*`, fed from the deployment's secret | Below. Unset `CELINE_KEYCLOAK_SMTP_HOST`: left alone |
| the built-in `account-console` client's default client scopes (`web-origins acr profile roles basic email`) | `bootstrap` itself (`ACCOUNT_CONSOLE_DEFAULT_SCOPES`) | What Keycloak gives a realm it creates. A realm imported from `config/keycloak/import/realm-celine.json` gets none, and the account console answers `403`. Missing ones are added, none removed; no other client is touched |
| `supportedLocales`, narrower | a deployment overlay, `bootstrap --overlay <file>` | The only key an overlay may change. It must keep `defaultLocale` (`it`) and name only `it`, `en`, `es` |
| themes, languages, lifespans, `registrationAllowed`, `resetPasswordAllowed`, brute-force tuning | `CELINE_KEYCLOAK_PLATFORM_<KEY>` | Overrides `platform.yaml` and any overlay. Below |

`verifyEmail` is deliberately **not** declared, and `platform.yaml` refuses it: the invitation
already carries `VERIFY_EMAIL`, and turning it on would stop every existing account with
`emailVerified: false` at its next sign-in. `passwordPolicy` stays at Keycloak's default.

A deployment overlay has the same shape as `platform.yaml`:

```yaml
realm_settings:
  supportedLocales: [it, en]
```

`bootstrap` prints the file each changed key came from.

#### The realm admin and the browser login client

The realm imports used to create both. They now come from declarations, so a realm that
`bootstrap` created has them too.

- **The operator realm admin** is `bootstrap`'s, in every environment, when
  `CELINE_KEYCLOAK_REALM_ADMIN_USERNAME` is set. It is created once, with
  `CELINE_KEYCLOAK_REALM_ADMIN_PASSWORD` (a secret), `_EMAIL`, and `_FIRST_NAME`/`_LAST_NAME`
  (default `Celine`/`Admin`; the realm's user profile requires both, and Keycloak refuses
  the sign-in without them). It is then kept in `CELINE_KEYCLOAK_REALM_ADMIN_GROUP`
  (`/admins`). Its password is never re-sent.
- **`oauth2_proxy`** is declared in `clients.yaml` and created by `sync`. `sync` also owns
  its secret, flows, redirect URIs, web origins, default scopes and audience mappers. Set:

  | Variable | Default | |
  |---|---|---|
  | `OAUTH2_PROXY_CLIENT_SECRET` | `oauth2_proxy` (refused outside dev) | the secret oauth2-proxy is configured with |
  | `CELINE_DOMAIN` | `celine.localhost` | redirect URIs: `sso`, `superset`, `webapp` and `assistant` on it, each `/*` |
  | `CELINE_URL_SCHEME` | `http` | `https` in a deployment |

  On a realm whose `oauth2_proxy` came from infra's import, the first `sync` replaces its
  redirect URIs with those four. The webapp entry is also what the provisioning service's
  invitation links return through.

#### Overriding a platform value from the environment

A deployment whose Keycloak differs from what the image assumes overrides a value instead of
mounting its own `platform.yaml`. The variable is `CELINE_KEYCLOAK_PLATFORM_` followed by the
realm key in upper snake case; the keys it accepts are `ENV_OVERRIDABLE_SETTINGS` in
[`platform.py`](../src/celine/policies/cli/keycloak/platform.py).

| Value | Effect |
|---|---|
| unset or empty | the declared value stands |
| `null` | the key is not declared: `bootstrap` leaves the realm's value alone, so a new realm keeps Keycloak's default. Nothing is reset |
| anything else | replaces the declared value, typed like the file: `true`/`false`, a non-negative integer, a string, or comma-separated locales |

Every check still runs on the result: a theme must be listed by the server, locales must
contain `defaultLocale`. A `CELINE_KEYCLOAK_PLATFORM_*` variable naming a key that is not
listed is refused: the features other commands require, `internationalizationEnabled` and the
username and email rules stay the image's.

A stock Keycloak, which ships no `rec` theme:

```yaml
CELINE_KEYCLOAK_PLATFORM_LOGIN_THEME: "null"
CELINE_KEYCLOAK_PLATFORM_EMAIL_THEME: "null"
```

#### SMTP

| Variable | Default | |
|---|---|---|
| `CELINE_KEYCLOAK_SMTP_HOST` | — | Unset or empty: `smtpServer` is not touched |
| `CELINE_KEYCLOAK_SMTP_PORT` | `587` | |
| `CELINE_KEYCLOAK_SMTP_FROM` | — | Required with a host |
| `CELINE_KEYCLOAK_SMTP_FROM_DISPLAY_NAME`, `CELINE_KEYCLOAK_SMTP_REPLY_TO` | — | |
| `CELINE_KEYCLOAK_SMTP_SSL`, `CELINE_KEYCLOAK_SMTP_STARTTLS` | `false` | |
| `CELINE_KEYCLOAK_SMTP_AUTH` | true when a user is set | |
| `CELINE_KEYCLOAK_SMTP_USER`, `CELINE_KEYCLOAK_SMTP_PASSWORD` | — | Both required with authentication. Pass the password from a secret |

Keycloak never returns the stored SMTP password, so `bootstrap` cannot compare it. Every other
field is diffed. The password is **sent on every run** and reported as
`smtpServer.password: write-only`, which is not a change: a second run still reports
`no change`. `bootstrap` never prints the password, in any environment.

### Locally

`mailpit` keeps every message in its UI at <http://localhost:8025> and delivers none.
The dev import (`config/keycloak/import/realm-celine.json`) points `smtpServer` at
`mailpit:1025`, which reaches **a realm created from it only**. On an existing local realm,
let `bootstrap` set it (the host is as Keycloak's container sees it):

```bash
CELINE_KEYCLOAK_SMTP_HOST=mailpit CELINE_KEYCLOAK_SMTP_PORT=1025 \
CELINE_KEYCLOAK_SMTP_FROM=noreply@celine.localhost CELINE_KEYCLOAK_SMTP_FROM_DISPLAY_NAME=CELINE \
  task keycloak:bootstrap
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
celine-policies keycloak sync-users example-rec.yaml

# the live registry, every community it holds
celine-policies keycloak sync-users --from-registry \
  --registry-url http://api.celine.localhost/rec-registry

# one community, and report divergence without writing anything
celine-policies keycloak sync-users --from-registry \
  --registry-url http://api.celine.localhost/rec-registry \
  --community example-renewable-community --check
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
