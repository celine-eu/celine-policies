"""Provisioning — making a participant's Keycloak account, and nothing else.

This package holds what it takes to put a person into the realm: the REC's
organization, its org groups, the account, its memberships. It is named for the
act rather than for identity, because `identity` is already taken by the
dataspace identity registry `../../onboarding` talks to and the two are
different things.

**It is the only thing that writes a participant account.** `keycloak sync-users`
calls it, and so does the service in front of it. `../../onboarding` holds no
Keycloak grant and makes no Admin API call — see the store's
`plans/provisioning-is-a-service-and-it-is-the-only-keycloak-writer.md`.

## The line this package sits on

| driven by | owner |
|---|---|
| `clients.yaml` — clients, scopes, audience mappers, realm groups | `keycloak sync`, a CLI |
| the registry — REC organizations, org groups, participants, memberships | this package |

That is not "structure versus lifecycle": a REC organization *is* realm
structure, and it is registry-driven, which is exactly why `sync` could never
create one.

## Why it imports from `celine.policies.cli`

`KeycloakAdminClient` lives under `cli/keycloak/`, which is where it was written
when the CLI was the only caller. Importing upwards from a service package is
the wrong direction and is deliberate for now: moving the client is a change
with its own blast radius and no bearing on whether this package is correct.
Nothing here imports `typer`, which is the property that actually matters — the
reporting stays with the caller.
"""

from celine.provisioning.models import (
    CommunityOutcome,
    OrganizationOutcome,
    OrganizationSpec,
    ParticipantOutcome,
)
from celine.provisioning.provisioner import Provisioner

__all__ = [
    "CommunityOutcome",
    "OrganizationOutcome",
    "OrganizationSpec",
    "ParticipantOutcome",
    "Provisioner",
]

# `service`, `routes` and `main` are deliberately absent from this list and not
# imported here: they pull FastAPI and the SDK's generated registry client, and
# every `keycloak` subcommand imports this package to reach `Provisioner`.
# Import them by module where they are actually wanted.
