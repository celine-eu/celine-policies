# Requirements

What this repository must do, stated so that a test can name it.

This directory started on 2026-09-27 with the provisioning service's part in a community
that starts clean ([ADR-0010](../decisions/ADR-0010-on-a-deployed-realm-members-arrive-through-onboarding.md)).
It does not yet describe the rest of the repository: the Keycloak CLI, most of the MQTT auth
backend and the Rego policies are described in [`docs/`](../architecture.md) and pinned by their
tests, and gain requirements here when a change needs one.

## Planned and implemented

A requirement is **implemented** unless it says otherwise: it describes what the code does
today, and at least one test declares it.

A requirement may land **ahead of the code**, marked with a line directly under its heading:

```markdown
**Status:** planned
```

A planned requirement describes the behaviour a change will deliver. It carries no test yet,
and is not reported as uncovered. It turns implemented — the status line is deleted — in the
change that makes its tests pass and tags them. A planned requirement that no change is
delivering any more is deleted, not left behind.

## How a requirement is verified

A test declares what it covers with a `@verifies REQ-####` tag in its docstring:

```python
def test_only_onboarding_holds_a_provisioning_scope():
    """Every holder of any `provisioning.*` scope other than the service itself.

    @verifies REQ-0001
    """
```

The mapping is a projection of the two and is never written by hand. Until the harness
checker is available in this checkout, the projection is a grep:

```bash
grep -rho --include='*.py' "@verifies REQ-[0-9]\{4\}" tests/ | sort | uniq -c
grep -rhoE '^### (REQ-[0-9]{4})' docs/specifications/*.md | sort
```

Read it both ways: an implemented requirement no test declares is unverified, and a tag
naming a requirement that does not exist is a typo.

## The requirements

| | |
|---|---|
| REQ-0001 – REQ-0003, REQ-0007 | [provisioning](provisioning.md) — who may call the provisioning service, what it creates for a community, and how it corrects an account |
| REQ-0004 – REQ-0005, REQ-0008 | [client grants](client-grants.md) — which scopes a client holds as default and which as optional, where a decision fixed it |
| REQ-0006, REQ-0011 – REQ-0013, REQ-0015 – REQ-0016, REQ-0020 | [Keycloak CLI](keycloak-cli.md) — what a `celine-policies keycloak` command may do, where a decision fixed it; the two-level authority model (`platform-admin` role, organization groups); the platform admin's second factor outside dev; the master realm reached through `bootstrap`'s own client and hardened outside dev; client secrets on disk only when asked |
| REQ-0009 – REQ-0010, REQ-0014, REQ-0017 | [MQTT auth](mqtt-auth.md) — what the MQTT auth backend refuses outside dev; no CORS; no superuser and no group grants; broker tokens bound by the `mqtt` scope, offered only to the broker declaration's own clients |
| REQ-0018 – REQ-0019 | [service surface](services.md) — both HTTP services: API docs only in dev or when opted in; every refusal an audit record naming the caller, and no claim in any log line |

## What is not here

- **Why** a choice was made — [`docs/decisions/`](../decisions/index.md).
- What the system *is* — [`docs/architecture.md`](../architecture.md) and
  [`docs/api-reference.md`](../api-reference.md).
- Anything broken — the issue tracker.
