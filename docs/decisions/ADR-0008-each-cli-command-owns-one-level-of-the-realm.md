# ADR-0008 — each CLI command owns one level of the realm, and checks the levels below it

**Date:** 2026-09-14
**Status:** accepted

## Context

Realm-wide state was written as a side effect of commands meant for something else:

- `sync-orgs` and `sync-users` turned Organizations on and converged the realm claim scopes
  and the oauth2-proxy audience mapper;
- `sync-users` created the realm role groups, without the realm roles the imports map onto them;
- `sync` turned fine-grained admin permissions on (ADR-0003).

So one realm setting had up to three writers, a change to how one was shaped had to be made
three times, and a dry run of a user import showed platform changes nobody asked for. And no
command at all wrote the sign-in settings: they reached a realm only through an import, which
Keycloak skips for a realm that already exists. The invitation work needed password reset,
languages, the email theme and the action-token lifespans on realms already in service, and
had nowhere to put them.

## Decision

The realm has three levels, and each has one writer:

| Level | Writer | Declaration |
|---|---|---|
| platform | `keycloak bootstrap` | `platform.yaml`, baked into the image; a deployment overlay that may narrow `supportedLocales` only; `CELINE_KEYCLOAK_BRUTE_FORCE_ENABLED`; `CELINE_KEYCLOAK_SMTP_*` |
| clients | `keycloak sync` | `clients.yaml` |
| organizations and users | the provisioning service, `sync-orgs`, `sync-users` | the registry, owners and REC YAML |

- **A command never writes a level it does not own.** It checks the levels it depends on,
  before its first write and in a dry run too, and refuses with the command to run.
- **`bootstrap` writes only the keys `platform.yaml` names**, as a partial realm update, so a
  key left out is left alone. It refuses `smtpServer`, `bruteForceProtected`, `verifyEmail`
  and `passwordPolicy` in the file, and a theme the server does not list.
- **The SMTP password is sent on every run** and not compared: Keycloak never returns it.

This supersedes the part of ADR-0003 in which `sync` enables `adminPermissionsEnabled`. The
rest of ADR-0003, as already superseded by ADR-0007, stands.

## Consequences

- **Order is load-bearing:** `bootstrap`, then `sync`, then the organization and user
  commands. A deployment that runs `sync-users` before any `bootstrap` now fails where it used
  to half-configure the realm, and infra's realm template never set `organizationsEnabled`.
- **Brute-force protection turns on** at a deployment's first `bootstrap` unless the variable
  says otherwise, because the default is on outside development environments.
- **A `bootstrap` run writes `smtpServer` every time** when SMTP authentication is configured,
  and its check cannot prove the password took.
- **The tempting undo** is to let `sync-users` "just enable" Organizations again, because it is
  one call and the refusal is an extra step. That brings back the second writer, and the
  platform changes in a user import's dry run, that this record exists to prevent.
- **The accepted keys must be real Keycloak keys.** One copied from infra's template
  (`maxLoginFailures`) is not, and Keycloak rejects the whole update. A test holds the
  accepted keys against the key set a real realm reads back.
