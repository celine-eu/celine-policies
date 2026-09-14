# Getting Started

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager
- [Task](https://taskfile.dev/) runner (optional, for convenience commands)
- Docker + Docker Compose (for the full stack)

## Install Dependencies

```bash
uv sync
```

## Keycloak Bootstrap and Sync

The CLI provisions Keycloak with the scopes and clients defined in `clients.yaml`.

### Step 1: Start Keycloak

Either start just Keycloak from the compose stack:

```bash
docker compose up keycloak -d
```

Or use an existing Keycloak instance and set `CELINE_KEYCLOAK_BASE_URL`.

### Step 2: Bootstrap Admin Client

Create a `celine-admin-cli` service account in Keycloak with realm-management roles:

```bash
celine-policies keycloak bootstrap --admin-user admin --admin-password admin
```

This writes the client secret to `.client.secrets.yaml`. Subsequent commands auto-load credentials from this file.

The file is the store of the credentials the CLI authenticates with, not a log of the last run: `bootstrap` and `sync` both merge into it, so neither deletes what the other wrote. It holds one realm's credentials — pointing a command at a different realm replaces its contents, and says so.

### Step 3: Sync Scopes and Clients

```bash
celine-policies keycloak sync
```

This reads `clients.yaml` and ensures Keycloak matches the desired state:
- Creates missing client scopes
- Creates missing service clients with generated secrets
- Assigns default scopes to clients
- Adds audience mappers for cross-service JWT validation

Use `--dry-run` to preview changes without applying them.

### Step 4: Sync Users (optional)

Import users from a `rec-registry` REC definition YAML:

```bash
celine-policies keycloak sync-users ../rec-registry/recs/rec-example.yaml \
    --password "demo" --mock
```

The `--mock` flag fills placeholder email/name fields for development.

Participants are also added to any group `clients.yaml` declares under
`admin_permissions`, so the service account granted over that group can see them — run
`keycloak sync` first, which is what creates the group. `--no-admin-groups` turns that off.
See [Realm administration](scopes-and-permissions.md#realm-administration).

### Step 5: Sync Organizations (optional)

Import organizations from an `owners.yaml` file:

```bash
celine-policies keycloak sync-orgs ../dataset-api/owners.yaml
```

## Running the Full Stack

```bash
docker compose up -d
```

This starts:

| Service | Port | Description |
|---------|------|-------------|
| `keycloak` | 8080 | Identity provider |
| `keycloak-sync` | — | Runs bootstrap + sync on startup, then exits |
| `sync-users` | — | Imports example users, then exits |
| `mqtt_auth` | 8009 | MQTT auth HTTP backend |
| `mosquitto` | 1883 (MQTT), 1884 (WebSocket) | MQTT broker |
| `redis` | — | Cache backend for mosquitto-go-auth |
| `oauth2-proxy` | 4180 | OAuth2 reverse proxy |
| `mailpit` | 1025 (SMTP), 8025 (UI) | Keeps Keycloak's outgoing mail; delivers none unless a relay is configured |

Verify the MQTT auth service is running:

```bash
curl http://localhost:8009/health
```

## Using Task Commands

```bash
task run              # Start MQTT auth dev server (with hot reload)
task debug            # Start with debugger attached
task test             # Run pytest suite
task keycloak:bootstrap   # Bootstrap admin client
task keycloak:sync        # Sync clients.yaml to Keycloak
task keycloak:sync-users  # Sync example REC users
task keycloak:sync-orgs   # Sync organizations from owners.yaml
```

## CLI Reference

All `celine-policies` commands accept `--help` for detailed usage:

```bash
celine-policies --help
celine-policies keycloak --help
celine-policies keycloak sync --help
```

### Common Options

Most keycloak commands share these connection options:

| Option | Env Variable | Default |
|--------|-------------|---------|
| `--base-url` | `CELINE_KEYCLOAK_BASE_URL` | `http://keycloak.celine.localhost` |
| `--realm` | `CELINE_KEYCLOAK_REALM` | `celine` |
| `--admin-user` | `CELINE_KEYCLOAK_ADMIN_USER` | — |
| `--admin-password` | `CELINE_KEYCLOAK_ADMIN_PASSWORD` | — |
| `--admin-client-id` | `CELINE_KEYCLOAK_ADMIN_CLIENT_ID` | `celine-admin-cli` |
| `--admin-client-secret` | `CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET` | (auto-loaded from `.client.secrets.yaml`) |
| `--secrets-file` | `CELINE_KEYCLOAK_SECRETS_FILE` | `.client.secrets.yaml` |

`sync` has a third input for the realm — `realm:` in the declaration it is applying — and it is the lowest-ranked one:

```text
--realm  >  CELINE_KEYCLOAK_REALM  >  realm: in clients.yaml  >  celine
```

The declaration aims a run nobody aimed, and nothing more. `sync` prints which input won, because the value alone does not say:

```console
Syncing to Keycloak: http://keycloak.celine.localhost realm=e2e-throwaway (from CELINE_KEYCLOAK_REALM)
```

## Testing

```bash
# Run the full test suite
uv run pytest

# Or via task
task test
```

## Next Steps

- Review [Scopes & Permissions](scopes-and-permissions.md) to understand the platform's OAuth model
- See [MQTT Integration](mqtt-integration.md) for topic patterns and broker configuration
- Check [Deployment](deployment.md) for the Docker Compose stack details
