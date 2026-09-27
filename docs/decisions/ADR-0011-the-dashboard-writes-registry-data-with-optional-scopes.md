# ADR-0011 — the manager dashboard writes a member's meter, role and area with optional registry scopes

**Date:** 2026-09-27
**Status:** accepted

## Context

A community manager needs to attach a member's meter and correct their role and area. Those
are registry data, so the manager dashboard (`svc-community`) writes them to the registry
directly; routing them through `../onboarding` would add a hop and make onboarding a general
member-administration service for data it does not own (requester, 2026-09-27).

Three things in this repository bear on that:

- **`svc-community` holds `rec-registry.read` as a default scope and nothing that writes.**
  Its one optional scope, `onboarding.members.invite`, is optional because the Digital Twin
  forwards this client's default-scope token to dataset-api, and a write capability must not
  travel there.
- **Every registry grant is registry-wide.** The registry authorises by scope; nothing in a
  scope names a community. `rec-registry.members.write` would also let the dashboard rewrite a
  member's `user_id`, DID and status.
- **`rec-registry.assets.write` is declared and held by nobody**, and there is no scope for
  "role and area only". The registry adds a dedicated profile route and a
  `members.profile.write` action for exactly that, which `rec-registry.members.write` and
  `rec-registry.admin` also satisfy.

The dashboard's declaration carries a promise, in `clients.yaml` and in
[scopes-and-permissions.md](../scopes-and-permissions.md#svc-community): "no email, user id,
DID or supply point leaves the BFF process". A meter write puts a sensor id on the wire from
the BFF to the registry.

## Decision

**Declare `rec-registry.members.profile.write`** — change one member's role and area, nothing
else — in the registry's scope family.

**`svc-community` gains two optional scopes, and no default one:**
`rec-registry.assets.write` for attaching and detaching a meter, and
`rec-registry.members.profile.write` for role and area. The BFF requests each only for the one
write that needs it, as it already does for `onboarding.members.invite`, so the token the
Digital Twin forwards carries neither.

**`rec-registry.members.write` stays refused to `svc-community`.** The narrow scope exists so
that it is never needed.

**Who may press is not decided here.** The registry grants reach every community; what keeps a
manager to their own REC is the dashboard's policy, and the dashboard's audit row is the only
record of who pressed. `rec-registry.read`, which the dashboard already holds, makes the same
trade for reads.

**The promise about what leaves the BFF is narrowed, not dropped.** The meter's sensor id is
entered as free text by the manager, in one dialog; nothing reads a list of candidate meters
for it, because an unattached meter belongs to no community and any candidate list would
disclose or mis-assign another community's meter. The id travels from the BFF to the
registry and nowhere else; the members list shows only whether a meter is attached; audit
rows and logs carry no sensor id. Email, user id, DID and supply point still never leave the
BFF. The sentence in `clients.yaml` and in the scope reference was rewritten in the change that
granted the scopes (REQ-0005), so that neither described a grant the realm did not have yet.

**`svc-onboarding` gains four scopes, with the changes that use them,** by the rule
`svc-community` already follows: a token the Digital Twin forwards carries no write
capability.

- **Optional, requested per call:** `provisioning.reconcile` (setting up a community, see
  [ADR-0010](ADR-0010-on-a-deployed-realm-members-arrive-through-onboarding.md)) and
  `rec-registry.community.write` (writing a community's areas and topology from its onboarding
  template). Onboarding requests each only for the one call that needs it, inside a registry
  sync a realm admin started.
- **Default:** `digital-twin.values.read` (resolving a supply address to a primary-substation
  boundary, and validating a template's boundary ids), and `rec-registry.read` (reading a
  community's areas, topology and member counts back for the sync's dry run, its prune count
  and the console's drift check). The registry's community `GET` routes derive the action
  `read`, which only `rec-registry.read` or `rec-registry.admin` satisfies, and onboarding
  holds neither today. Both are reads; `svc-community` holds the same two by default. No new
  scope is declared for the drift check.

## Consequences

- **The dashboard can write any community's meters, roles and areas** if its policy is wrong.
  That is inherent in registry-wide grants, and is the reason the dashboard's per-REC policy
  and audit row are tested there, not here.
- **`tests/test_provisioning_scope_holders.py` pins `svc-community`'s optional scopes to
  exactly `onboarding.members.invite`, `rec-registry.assets.write` and
  `rec-registry.members.profile.write`**, changed in the change that granted the two, and still
  asserts no `provisioning.*` scope. `tests/test_community_registry_scopes.py` pins the rest of
  the shape (REQ-0005): both writes optional, none default, never `members.write` or `.admin`. The test that onboarding holds `participants.write` "and
  nothing wider" gains `provisioning.reconcile` as an optional scope in the change that grants
  it (REQ-0004).
- **Onboarding's default token can read every community's registry data**, as the dashboard's
  already can. The writes stay out of it.
- **The tempting shortcut is `rec-registry.members.write`**, because it already exists and
  covers role and area. It also covers `user_id`, DID and status, which the dashboard must not
  be able to rewrite.
- **The scope descriptions and the registry's policy must agree.** The superset
  (`members.write` and `.admin` satisfy `members.profile.write`) is the registry's; this
  repository only declares the name and who holds it.
