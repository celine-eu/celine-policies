# celine-policies

Authentication, authorization, and identity management for the CELINE platform.

This repository provides two services:

1. **`mqtt_auth`** — A FastAPI HTTP backend for [mosquitto-go-auth](https://github.com/iegomez/mosquitto-go-auth) that validates JWTs and evaluates OPA (Rego) policies to control MQTT topic access.
2. **`celine-policies` CLI** — A typer-based CLI that performs idempotent synchronization of OAuth scopes, service clients, users, and organizations into Keycloak.

It also ships a custom Keycloak Docker image with the `rec` login theme (see [`keycloak/README.md`](keycloak/README.md)).

## Quick Start

```bash
# Install dependencies
uv sync

# Bootstrap Keycloak admin client and sync scopes/clients
task keycloak:bootstrap
task keycloak:sync

# Start the full stack (Keycloak, MQTT auth, Mosquitto, Redis, oauth2-proxy)
docker compose up -d

# Verify MQTT auth health
curl http://localhost:8009/health
```

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.md) | Setup, CLI commands, and first sync |
| [Architecture](docs/architecture.md) | System design and component overview |
| [API Reference](docs/api-reference.md) | MQTT auth HTTP endpoints |
| [Scopes & Permissions](docs/scopes-and-permissions.md) | OAuth scopes and client configuration |
| [MQTT Integration](docs/mqtt-integration.md) | Topic patterns, ACL policies, broker config |
| [Deployment](docs/deployment.md) | Docker Compose stack and configuration |

## Project Structure

```
celine-policies/
├── src/celine/
│   ├── mqtt_auth/          # FastAPI MQTT auth service
│   │   ├── main.py         # App factory (create_app)
│   │   ├── routes.py       # /user, /acl, /superuser endpoints
│   │   ├── models.py       # Pydantic request/response models
│   │   └── config.py       # MqttAuthSettings (pydantic-settings)
│   └── policies/cli/       # celine-policies CLI
│       ├── main.py          # Typer entrypoint
│       └── keycloak/        # Keycloak management commands
│           ├── commands/    # bootstrap, sync, sync-users, sync-orgs, etc.
│           ├── client.py    # KeycloakAdminClient (async httpx)
│           ├── models.py    # Config models for clients.yaml
│           ├── settings.py  # KeycloakSettings, SyncUsersSettings
│           └── sync.py      # Sync plan computation and application
├── policies/celine/        # Rego policy files
│   ├── mqtt/acl.rego       # MQTT topic ACL rules
│   └── scopes.rego         # Shared scope/group helpers
├── clients.yaml            # Platform scopes and service client definitions
├── keycloak/               # Custom Keycloak image + rec login theme
├── config/
│   ├── keycloak/import/    # Realm import JSON
│   ├── mosquitto/          # mosquitto.conf
│   └── oauth2-proxy/       # oauth2-proxy.cfg
├── tests/                  # Pytest test suite
├── docker-compose.yaml     # Full development stack
├── Dockerfile              # MQTT auth service image
├── taskfile.yaml           # Task runner commands
└── pyproject.toml          # Package definition (uv + hatchling)
```

## CLI Commands

```bash
celine-policies keycloak bootstrap       # Create admin-cli service account in Keycloak
celine-policies keycloak sync            # Sync clients.yaml scopes/clients to Keycloak
celine-policies keycloak sync-users      # Import users from REC registry YAML
celine-policies keycloak sync-orgs       # Import organizations from owners YAML
celine-policies keycloak set-password    # Set a user's password
celine-policies keycloak set-user-organization  # Assign user to org + groups
celine-policies keycloak status          # Show current Keycloak state
```

## Development

```bash
# Run MQTT auth dev server
task run

# Run tests
task test

# Release (semantic-release)
task release
```

## License

Apache 2
