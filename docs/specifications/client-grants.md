# Client grants

What a client declared in `clients.yaml` holds, where a decision fixed it and a test can pin
it. The scope families are described in
[scopes-and-permissions.md](../scopes-and-permissions.md).

---

### REQ-0004 — `svc-onboarding` holds its write scopes as optional and its reads as default

For the manager features and the registry sync
([ADR-0011](../decisions/ADR-0011-the-dashboard-writes-registry-data-with-optional-scopes.md)),
`svc-onboarding`'s declaration in `clients.yaml` holds, over `clients.yaml` alone and merged
with the ds-host overlay:

- **`provisioning.reconcile` and `rec-registry.community.write` as optional scopes**, and in
  neither as a default scope. Onboarding requests each for the one call that needs it, so a
  default-scope token of this client carries no community write and no sweep.
- **`digital-twin.values.read` and `rec-registry.read` as default scopes.** The first resolves
  a supply address to a boundary and validates a template's boundary ids; the second reads a
  community's areas, topology and member counts, which the registry's community `GET` routes
  require.
- **Exactly those two optional scopes.** A token onboarding uses for everything else carries
  neither, so the provisioning service refuses it on `POST /reconcile/{community}` with
  `403 insufficient_scope`; a token that requested `provisioning.reconcile` is accepted there.
- **Nothing wider than before in the provisioning family.** `provisioning.participants.write`
  stays a default scope, `provisioning.admin` stays refused, and REQ-0001 still holds.

### REQ-0005 — `svc-community` holds its registry writes as optional scopes, and no wider one

For the manager's meter and profile dialogs
([ADR-0011](../decisions/ADR-0011-the-dashboard-writes-registry-data-with-optional-scopes.md)),
over `clients.yaml` alone and merged with the ds-host overlay:

- **`rec-registry.members.profile.write` is declared** in the registry's family, owned by
  `svc-rec-registry`: change one member's role and area, nothing else.
- **`svc-community` holds `rec-registry.assets.write` and `rec-registry.members.profile.write`
  as optional scopes**, and a sync plans both as optional assignments. The BFF requests each
  for the one write that needs it, so the default-scope token the Digital Twin forwards carries
  no registry write: its only registry scope is `rec-registry.read`.
- **`svc-community` never holds `rec-registry.members.write` or `rec-registry.admin`**, as a
  default or an optional scope. Its registry scopes are exactly `rec-registry.read` (default)
  and the two writes (optional).
