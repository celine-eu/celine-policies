# ADR-0004 — A group grant carries `view`, and a group belongs to one client

**Date:** 2026-09-10
**Status:** accepted

Refines [ADR-0003](ADR-0003-declare-realm-administration-as-a-group-scoped-permission.md),
which it does not supersede: the grant is still declared, still group-scoped, and still
expresses nothing realm-wide. Two properties of it were wrong, and both were found by
running it.

## Context

ADR-0003 shipped `svc-onboarding` a grant of
`manage-members, manage-membership, view-members` over `/participants`, measured to permit
creating a participant and administering an existing one. `../onboarding` then ran under
it, and measurement on the running 26.6.0 found two things the earlier measurements could
not see, because each was taken one grant per throwaway realm.

**The member scopes cannot name the group they are about.** Holding exactly those three,
*every* route to the group's own id answers `403`:

| call | three member scopes | with `view` added |
|---|---|---|
| `GET /group-by-path/participants` | **403** | 200 |
| `GET /groups/{id}` on the administered group | **403** | 200 |
| `GET /groups` and `GET /groups?search=participants` | 403 | 403 |
| `GET /groups/{id}/members` | 200 | 200 |
| `POST /users` into the group | 201 | 201 |

Every member call is addressed by that id. A grant without `view` can therefore create a
participant and can never find one again — and because the consumer resolves its group
lazily, provisioning a new login still works and only *adoption* fails: a re-approval, a
retried enablement step, a `403` a long way from the declaration that caused it.

**Two clients granted the same group deny each other.** A permission for `svc-a` and
another for `svc-b` on `/participants` leaves **both** with `403` on everything — creating,
reading members, resolving the group. The admin-permissions resource server's
`decisionStrategy` is `UNANIMOUS` and so is each permission's, so a permission whose client
policy does not name you votes *against* you. Keycloak creates both with a `201` and
reports nothing. Nothing declares two clients on one group today, and `sync` would have
produced it the moment somebody did — silently revoking the grant from the client that was
already working.

## Decision

**`view` is required in practice and warned about, not refused.** `clients.yaml` gains it
for `svc-onboarding`, and `compute_sync_plan` warns when a declaration carries any
member-addressed scope without `view`, exactly as it already warns on the
`manage-members` / `manage-membership` half-grant. It is a warning rather than a refusal
for the same reason: a permission whose scopes are all member-addressed is a coherent
narrower grant to want, and the warning names what will break.

Granting `view` does not widen the reach beyond the group. `GET /groups` — listing the
realm's groups — stays `403`, because it is a realm-wide act.

**A group is declared by at most one client, and a second declaration is refused when the
file is loaded.** `malformed_admin_permissions()` reports it alongside the unknown-scope
and nested-path checks, before anything is authenticated.

Two alternatives were weighed and rejected:

- *One permission per group whose client policy names every declared client.* A permission
  carries one scope list, so every co-declaring client would receive the **union** — a
  client that declared `view-members` silently gaining `manage-members`. The mechanism
  exists to make a grant exact; a union defeats it.
- *`decisionStrategy: AFFIRMATIVE` on the admin-permissions resource server.* It keeps each
  client's scopes exact, but it changes how **every** permission under that resource server
  combines, including ones an operator made by hand in the console. This tool's discipline
  is that it touches only what carries its sentinel, and a realm-wide evaluation change is
  the opposite of that.

## Consequences

**The platform cannot express two services administering one group.** Nothing needs it. If
something does, the choice above is the one to reopen, and the two candidates are recorded
here rather than re-derived. A refusal is recoverable by editing a file; the silent
revocation it prevents is not.

**A grant declared before this change keeps working and starts warning.** The warning does
not block a sync and the permission is still applied, so an existing realm converges on the
next run rather than failing.

**`GET /groups/{id}/members` ignores `search` entirely.** Measured on a group of 130:
`?search=`, `?exact=`, any value — the endpoint answers 200 with every member, and its only
parameters are `first`, `max` and `briefRepresentation`. ADR-0003 closes by naming that
call as the containment-preserving way for `../onboarding` to look somebody up. The call is
permitted; the filter is not real, so the lookup is a paged scan matched by the caller. It
does not change this decision and it does change what the consumer must implement.
