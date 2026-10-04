# ADR-0013 — `bootstrap` owns the admin second factor, on unless the environment is dev

**Date:** 2026-10-04
**Status:** accepted

## Context

The platform admin's second factor reached a realm only through infra's realm import
(`keycloak.admin_mfa`, the flow `browser-admin-second-factor`). Keycloak skips an import for a
realm that already exists, so:

- turning the switch on for a realm in service changed nothing;
- the flow's condition named the realm role `admin`, which `bootstrap` now deletes (ADR-0012).
  On a realm imported with the flow, the condition kept naming a role nobody holds, and platform
  admins signed in with a password alone, without any error.

The requester asked on 2026-10-04 that staging, and every other environment that is not dev,
have admin MFA, set up by `bootstrap`.

## Decision

- **`bootstrap` is the one writer of the realm's browser flow** (the platform level,
  ADR-0008). It converges `browser-admin-second-factor` to the shape measured on Keycloak
  26.7.3, conditioned on `platform-admin`, and binds it, from any starting state. A condition on
  a retired role anywhere else is repointed to `platform-admin`.
- **`CELINE_KEYCLOAK_ADMIN_MFA_REQUIRED` decides; unset, it is on unless `ENV` is exactly
  `dev`**, the rule brute-force protection already follows. A deployment that says nothing gets
  the second factor; a developer's local realm does not.
- **The realm import no longer declares the flow.** Infra drops `keycloak.admin_mfa` from its
  realm template and passes the environment to the bootstrap job instead. One owner, so the
  import and the job can never disagree on the role or the shape.
- When it is off, Keycloak's own `browser` flow is bound and the custom flow is left in place,
  unbound. Outside dev, unbinding it is destructive and needs `--allow-destructive`.

## Consequences

- **A platform admin enrols TOTP and recovery codes at the first sign-in after the first
  `bootstrap` run with it on.** The flow runs before required actions, so an admin's first
  password sign-in enrols TOTP before any passkey.
- **A flow of another shape under the same name is deleted and rebuilt.** Keycloak refuses to
  delete the bound browser flow, so for the length of the rebuild (a few Admin API calls) the
  realm is bound to Keycloak's own `browser`, which still asks a user who has TOTP for it.
- **The password grant is not covered.** The flow is the browser flow. A client with
  `directAccessGrantsEnabled` (`oauth2_proxy` has it) still lets a platform admin's password
  alone obtain a token, to whoever holds that client's secret.
- **Recovery is by another admin**, who removes both the TOTP and the recovery codes; removing
  only the TOTP leaves the codes as a factor and TOTP is not enrolled again. The master realm's
  admin was the break-glass account; outside dev it now has a second factor too (ADR-0014), and
  the last resort is Keycloak's own `kc.sh bootstrap-admin`.
- **The tempting undo** is to put the flow back in the realm import "for new realms". That makes
  two writers again, and the import's copy is exactly what went stale when the role changed.
