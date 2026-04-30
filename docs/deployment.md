# Deployment

Configuration and deployment details for the celine-policies stack.

## Docker Compose Stack

The `docker-compose.yaml` defines the full development stack:

| Service | Image | Port | Description |
|---------|-------|------|-------------|
| `keycloak` | Custom (from `keycloak/Dockerfile`) | 8080 | Identity provider with `rec` login theme |
| `keycloak-sync` | Same as `mqtt_auth` | — | Runs `bootstrap` + `sync` on startup, then exits |
| `sync-users` | Same as `mqtt_auth` | — | Imports example REC users, then exits |
| `mqtt_auth` | From `./Dockerfile` | 8009 | MQTT auth HTTP backend |
| `mosquitto` | `ghcr.io/lhns/mosquitto-go-auth:3.3.0-mosquitto_2.0.22` | 1883, 1884 | MQTT broker (TCP + WebSocket) |
| `redis` | `redis:7.2-alpine` | — | Cache backend |
| `oauth2-proxy` | `quay.io/oauth2-proxy/oauth2-proxy:v7.11.0` | 4180 | OAuth2 reverse proxy |

### Startup Order

1. **keycloak** starts first (health check on port 9000)
2. **keycloak-sync** runs bootstrap + sync, then exits
3. **sync-users** imports example users, then exits
4. **mqtt_auth** starts after keycloak-sync and sync-users complete
5. **mosquitto** starts after redis is up and mqtt_auth is healthy

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
| `CELINE_KEYCLOAK_REALM` | `celine` | Target realm |
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

### Keycloak

The Keycloak service uses the custom image from `keycloak/Dockerfile` (KC 26.6.0 + rec theme). Key environment variables:

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

- Base: `quay.io/keycloak/keycloak:26.6.0`
- Adds the `rec` login theme (see [`keycloak/README.md`](../keycloak/README.md))
- Pre-builds Keycloak at image build time for faster startup
- Version tracked in `keycloak/version.txt` (`26.6.0-1.0.3`)

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
