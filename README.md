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

### `ENV` — production safety

Every client secret in `clients.yaml` is written as `${SVC_X_SECRET:-svc-x}`, so
an unset variable resolves the secret to the client id itself. That is the point
locally; against a real realm it installs a credential anyone can derive from the
client list, and nothing downstream ever complains.

`keycloak sync` therefore **defaults to `ENV=prod`** and refuses to run when any
client would receive such a placeholder, naming each offending client and the
variable that fixes it. It fails before authenticating, so a misconfigured
deployment stops on its own machine rather than halfway through a live realm.

```bash
ENV=dev celine-policies keycloak sync    # accept the clients.yaml fallbacks
SVC_DATASET_SECRET=... celine-policies keycloak sync   # or supply real secrets
```

`taskfile.yaml` exports `ENV=dev` for the whole file, so `task keycloak:sync` and
friends behave as before. Resolution order is `CELINE_KEYCLOAK_ENV`, `CELINE_ENV`,
then plain `ENV`; `dev`, `development`, `local`, `test` and `ci` disable the
check, and **anything else — including a typo or nothing at all — is production**.
Declaring no `secret:` at all is always accepted: Keycloak then generates one,
which is the recommended production shape.

### One realm, more than one file

`sync` recomputes the grants of every client **present** in the file it is given. A file
that describes only part of a realm therefore does not leave the rest alone: an absent
client is an orphan and survives without `--prune`, but a client that stays is narrowed to
whatever grants that file declares — silently, with nothing deleted and no flag involved.

So when a realm is declared by more than one party, pass every file and let the loader
merge them:

```bash
celine-policies keycloak sync clients.yaml \
    --overlay clients.ds-host.yaml \
    --overlay /path/to/ds/clients.yaml
```

`--overlay` is repeatable. Merging happens before anything else, so the placeholder-secret
guard and the scope-reference check see the whole realm rather than one file's view of it.

The rule is **ownership, not precedence** — no file is subordinate and there is no
last-wins:

| | |
|---|---|
| a client's identity | declared by **exactly one** file: `name`, `description`, `secret`, `scopes_prefix`, `service_account_enabled` |
| a client's grants | added by **any** file, with `client_id` plus `default_scopes` / `optional_scopes` / `extra_audiences` and nothing else |
| a scope | declared once, or identically more than once; a conflicting redefinition is an error |
| `realm`, `oauth2_proxy_client` | stated by any file; two files disagreeing is an error |
| a `scopes_prefix` | claimed by one client only — it decides where every audience mapper for those scopes points |

### Which files this repository ships

| file | declares | mounted |
|---|---|---|
| `clients.yaml` | celine's own services | always — it is a whole realm on its own |
| `clients.ds-host.yaml` | the grants celine adds to the dataspace's clients | only where a dataspace is deployed, and only with ds's file |

**The dataspace is optional, so the base file does not require it.** `clients.yaml`
declares nothing about ds — no client, no scope family — and syncing it alone produces a
correct celine realm. Where a dataspace is deployed, its clients are declared by ds's own
file and celine adds grants to them from `clients.ds-host.yaml`.

Forgetting ds's file is refused rather than survived, and no keyword is needed for it:
every entry in the host overlay is grants-only, so without ds's declaration they name
clients nobody owns, and the sync stops before authenticating rather than creating eight
clients with no name and generated secrets.

A file that genuinely cannot be synced on its own may still say so, and the file that
answers it identifies itself by name — not by path, because a deployment mounts a file
wherever it likes:

```yaml
# a base file that is only ever half a realm
requires: [ds]        # refuse to sync without the declaration called 'ds'

# the file that answers it
overlay: ds           # this is that declaration
```

Use it only where the base file is genuinely incomplete without the other. Putting
`requires:` on a file that describes a working realm makes an optional component
mandatory — which is why neither file above carries one.

A grant naming a scope **no** file declares is refused the same way, in every environment
and with no flag to accept it: the scope would never be created, so the grant would be
skipped and the service would get a 403 the first time it needed it. This used to be a
warning that synced anyway and failed at the end, with the realm already rewritten — see
[ADR-0002](docs/decisions/ADR-0002-undefined-scope-grants-are-fatal.md). See
[ADR-0001](docs/decisions/ADR-0001-merge-in-the-loader.md) for why this is merged in the
loader rather than pre-merged into a generated file.

## Dataspace Integration

The CLI manages Keycloak resources for the CELINE dataspace layer (identity
registry, onboarding, portal).

### `dataspace` claim scope

`ensure_realm_claim_scopes()` creates a `dataspace` client scope with an
`oidc-usermodel-attribute-mapper` that maps the Keycloak user attribute
`dataspace_did` into a `dataspace_did` JWT claim (id, access, and userinfo
tokens). The scope is assigned as a default scope on the `oauth2_proxy` client,
so every user JWT automatically carries the claim when the attribute is set.

### `identity-registry.admin` scope

A standard OAuth scope granting admin access to the dataspace identity-registry
API. It follows the `{service}.admin` naming convention, and is declared in
`clients.ds-host.yaml` because celine is the only party that grants it: ds omits
every `*.admin` from what it carries into a host realm, on the grounds that a
long-lived process should not hold a superset over every permission of a service.

### Dataspace service clients

They follow the `svc-ds-*` naming convention to distinguish dataspace services
from platform services (`svc-*`), and **they are declared by ds, not here** —
ds owns their identity and the `identity-registry.*`, `connector.*`,
`provenance.*` and `catalog.*` vocabularies. This repository used to carry a
hand-pasted copy of that declaration; it drifted, and the copy is gone. See
[ADR-0001](docs/decisions/ADR-0001-merge-in-the-loader.md).

What celine decides about them is in `clients.ds-host.yaml`, one grants-only
entry per client:

- **`svc-ds-identity-registry`** — `identity-registry.admin`. ds drops every `*.admin` from what it carries into a host realm; this realm drives the registry as an operator surface, so it grants the superset and declares it.
- **`svc-ds-onboarding`** — `rec-registry.members.write`. rec-registry is celine's own service, so ds's file cannot carry this grant.
- **`svc-ds-portal`** — the host-side console grants, including `dataset.query` / `dataset.read` against celine's dataset-api.
- **`svc-ds-dataset-api`** — `dataset.admin` and the `svc-dataset-api` audience. `dataset.*` is celine's vocabulary on celine's data plane; this client is the dataset API's outbound identity ([spindoxlabs/ds#14](https://github.com/spindoxlabs/ds/issues/14)).

The other four ds clients — `svc-ds-connector`, `svc-ds-provenance`,
`svc-ds-federated-catalog`, `svc-edc` — need nothing from celine and appear in
neither file.

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
