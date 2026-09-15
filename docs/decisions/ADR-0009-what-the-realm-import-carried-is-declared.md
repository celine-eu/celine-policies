# ADR-0009 — what the realm import carried is declared: the browser client, the realm admin, the dev users

**Date:** 2026-09-14
**Status:** accepted

## Context

ADR-0008 made `bootstrap` able to create a realm, with the realm import to be dropped once
parity is proven. The first run of a realm created without the import showed what else the
imports had been carrying that nothing declared:

- **the `oauth2_proxy` client.** On such a realm `sync` re-planned 13 audience mappers every run,
  for a client that did not exist, and nobody could sign in;
- **a realm admin** (`celine-admin`, in `/admins`), created by infra's import in every
  environment;
- **four development users**, in the dev import.

`sync` could not have declared `oauth2_proxy` anyway: it wrote every client as a service account
and forced every login flow off on update.

## Decision

- **`oauth2_proxy` is declared in `clients.yaml`.** A client gains an optional `browser:` block
  (redirect URIs, web origins, implicit flow, direct access grants, access-token lifespan).
  `sync` manages exactly those keys, plus the secret and default scopes, on a client that
  declares the block, and never compares them on one that does not. The proxy's audience
  mappers stay with the `oauth2_proxy_client` rule, never also with the per-client rule. Its
  redirect URIs are interpolated from `CELINE_DOMAIN` and `CELINE_URL_SCHEME`.
- **`bootstrap` creates the operator realm admin** from `CELINE_KEYCLOAK_REALM_ADMIN_*`, in every
  environment, once, and keeps it in its group. Its password is never re-sent.
- **`seed-dev-users` creates the development users** from `config/keycloak/dev-users.yaml`, and
  refuses outside a development `ENV`.

All three by the requester, 2026-09-14.

## Consequences

- **A deployment's first `sync` rewrites `oauth2_proxy`:**
  - its redirect URIs become `sso`, `superset`, `webapp` and `assistant` on the domain, each
    `/*` (infra's import had `sso …/oauth2/callback` and `superset …/*/`);
  - its secret becomes `OAUTH2_PROXY_CLIENT_SECRET`, and a wrong value there breaks browser
    login for everyone.
- **The local realm's tokens change:** `oauth2_proxy` gains `roles`, `web-origins` and `acr` as
  default scopes, which infra's import already gave it, so local tokens now carry `realm_access`
  like deployed ones.
- **Both imports enable the implicit flow and direct access grants on `oauth2_proxy`**, and the
  declaration keeps them. Turning them off is a separate decision.
- **The tempting undo** is to move the client back to "external" because `sync` now writes a
  login-critical client. Doing so brings back a realm that `bootstrap` can create but nobody
  can sign in to.
