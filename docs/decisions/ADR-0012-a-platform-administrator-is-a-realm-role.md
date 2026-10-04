# ADR-0012 — a platform administrator is a realm role; realm groups carry no authority

**Date:** 2026-10-03
**Status:** accepted

## Context

The realm-wide role groups (`/admins`, `/managers`, `/editors`, `/viewers`, each mapped onto a
realm role `admin`, `manager`, `editor`, `viewer`) were designed for one Keycloak per
organization. The platform now runs many organizations in one realm, and every organization
has groups with **the same names**, whose path in a token is also `/admins`. A token therefore
carried `admins` at two levels with two meanings, and every reader that flattened them, or
guessed between `admin` and `admins`, `/admins` and `admins`, was one mistake from letting
one community's operator act on all of them.

The `groups` claim was also written twice: by the `groups` client scope (`full.path: true`)
and by a client-level mapper on `oauth2_proxy` (`full.path: false`). Readers disagreed on which
form to expect.

## Decision

Exactly two levels (requester, 2026-10-03):

- **`platform-admin`, a realm role,** is the only platform-wide grant. It reaches a token in
  `realm_access.roles`. `bootstrap` creates it, gives it to the operator realm admin and to the
  users a deployment lists, and removes it from any group or composite that would share it.
- **An organization's own groups** (`admins > managers > editors > viewers`) are valid only
  inside that organization. They reach a token only in `organization.<alias>.groups`.

Realm groups `/admins`, `/managers`, `/editors`, `/viewers` and realm roles `admin`, `manager`,
`editor`, `viewer` are removed by `bootstrap`, from whatever state a realm is in. No mapper
writes a top-level `groups` claim any more; a realm group still present in a token grants
nothing. Every client that signs people in holds the `roles` scope.

Policy input follows the same split. A service puts the person's realm roles in
`input.subject.roles` and tests `"platform-admin" in input.subject.roles`; it never puts a
realm role or a realm group into `input.subject.groups`, which holds only the groups of the one
organization the decision is about. No helper merges the two levels into one list
(`celine-sdk` removed `extract_groups` and `realm_groups` in 2.0.0).

The MQTT backend has no superuser and no group grants: user or service is decided by the token's
kind, and a service is judged by its scopes.

No phased rollout and no compatibility path for the old groups: the change ships whole in one
deployment, and every reader moves to the role in the same release.

## Consequences

- **`bootstrap` now deletes realm objects.** It deletes exactly the names `platform.yaml` lists
  under `retired`, and nothing else; an organization's group of the same name is not a realm
  group and is never touched.
- **The `groups` client scope is gone.** A client that requested `scope=groups` explicitly would
  now be refused; none does (oauth2-proxy requests `openid email profile organization:*`).
- **Platform admins are few and named.** A deployment lists them in its overlay
  (`platform_admin.users`); a grant given by hand in the console is reported, not revoked.
- **ADR-0009 is superseded in one point.** `bootstrap` still creates the operator realm admin,
  but no longer "keeps it in its group": it holds the role `platform-admin` directly and is in
  no realm group.
- **The tempting undo** is a realm group `platform-admins`. It keeps the ambiguous `groups`
  claim and moves no reader less than the role does; the role is already emitted and already
  what Keycloak's MFA condition (`conditional-user-role`) tests.
