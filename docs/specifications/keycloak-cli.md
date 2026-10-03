# Keycloak CLI

The `celine-policies keycloak` commands, where a decision fixed what a command may do. The
commands are described in [architecture.md](../architecture.md) and
[deployment.md](../deployment.md).

---

### REQ-0006 — `sync-users` runs only in a development environment

`celine-policies keycloak sync-users` **refuses to run unless the environment names a
development one**: `ENV` (or `CELINE_KEYCLOAK_ENV`, `CELINE_ENV`, which outrank it) is
exactly `dev` — the guard `seed-dev-users` uses. Unset, `prod`, `staging`, `development`,
`local`, `test`, `ci` or any other value exits `1` with a message that names `ENV=dev`.

> Until 2026-10 `development`, `local`, `test` and `ci` relaxed it too. The platform rule
> (`celine.sdk.posture`) is that only `dev` relaxes, and ADR-0010's wording "`ENV=dev`" now
> means exactly that value.

The refusal comes **before a source is read or Keycloak is asked anything**, and holds for
`--dry-run` and `--check` too.

On a deployed realm members arrive through onboarding and a community's organization through
the provisioning reconcile; the YAML seed and `sync-users` are local development
([ADR-0010](../decisions/ADR-0010-on-a-deployed-realm-members-arrive-through-onboarding.md)).
