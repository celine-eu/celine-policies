# ADR-0014 — `bootstrap` reaches the master realm through its own client, and hardens it outside dev

**Date:** 2026-10-04
**Status:** accepted

## Context

The master realm holds the Keycloak-wide administrator, the account every deployment
configures the platform with, and Keycloak is public. Until now `bootstrap` signed in to
master as that administrator with a password, and never touched master's own settings:
master had no brute-force detection and no second factor.

The requester decided on 2026-10-04 that, outside dev, master gets brute-force detection and a
second factor for its administrators, set up by `bootstrap`; that `bootstrap` first creates a
dedicated master client whose secret is a configured value from the deployment's secrets, and
then uses that client; and that only the client's token may set up the second factor and
brute force, never the administrator's own, "or it would be cut off".

## Decision

- **A dedicated master client, `svc-celine-policies-bootstrap`**
  (`CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_ID`). Confidential, service account only (no browser
  flow, no password grant). Its secret is `CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_SECRET`, never
  generated, never printed, never written to the secrets file, and converged onto the client
  on every run. Outside dev it is required (at least 32 characters) and `bootstrap` refuses
  before contacting Keycloak without it.
- **Sign-in order:** the client first; the master admin user only when the client cannot sign
  in (it does not exist yet, or holds another secret), and then only to create or repair the
  client. `bootstrap` then signs in again as the client, checks that the token is the client's
  own (`azp`, issued by master), and does everything else with it, the platform realm
  included. The other commands (`sync` in a deployment's shell) try the client before the
  admin user too.
- **The client holds master's realm role `admin`.** Measured on 26.7.3: in a realm with
  fine-grained admin permissions (`adminPermissionsEnabled`, which `platform.yaml` declares) a
  master principal that is not a master `admin` gets 403 mapping any administration role, even
  holding every `<realm>-realm` role, even as the creator of the realm. `bootstrap` must grant
  the admin CLI client its realm-management roles, so nothing narrower works.
- **Outside dev, master is hardened with that token only:** `bruteForceProtected` and the
  platform realm's declared brute-force tuning; the browser flow of ADR-0013 without the
  organization step, conditioned on master's role `admin`, bound; and `CONFIGURE_TOTP` on every
  master `admin` holder who has no one-time code. The switches are the platform realm's
  (`CELINE_KEYCLOAK_BRUTE_FORCE_ENABLED`, `CELINE_KEYCLOAK_ADMIN_MFA_REQUIRED`, both on unless
  `ENV=dev`). The writes refuse any session whose identity is not the client signed in and
  checked by this process.
- **In dev** master is not touched; the client is managed only if its secret is set.

## Consequences

- **After the first run the master admin's password grant fails** ("Account is not fully set
  up" until TOTP is enrolled, then a code is required). That is the point. Every later run,
  and the shell's `sync`, signs in as the client; the deployment passes the client's secret to
  both.
- **The client is as powerful as the account it replaces.** What changes is how it can be
  used: no browser sign-in, no password grant, a long configured secret, held by the
  deployment's secrets only. Losing that secret is losing master; it is rotated through the
  console and the secrets together.
- **Recovery** is Keycloak's own `kc.sh bootstrap-admin` (a temporary admin user or service
  client), not a bypass in `bootstrap`. ADR-0013's "the master realm's admin is not subject to
  the flow and is the break-glass account" no longer holds outside dev.
- **The tempting undo** is to let `bootstrap` harden master with the admin's own token when
  the client is missing. That is exactly the run that locks the operator out halfway; the
  refusal is the feature.
