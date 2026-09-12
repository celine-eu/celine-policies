# ADR-0006 — the REC registry is the source of members, and a YAML file is a seed

**Date:** 2026-09-12
**Status:** accepted

## Context

`sync-users` reconciled the realm against a **file**. `load_rec_participants` took a
`Path`, so whatever snapshot an operator exported was what the realm was made to match.

That was true when a REC's membership was authored by hand. It is not true now:
`../onboarding` writes a member to the registry on every approval, so a file is a picture
of the community at export time and everybody approved since it was taken is invisible to
the sync. The registry's own import endpoint says as much — *"members now arrive at runtime
through the member API, so re-importing a stale export is the most likely way to lose
them"*.

The cost was measured on the demo3 deployment, 2026-09-11: **10 of 45 `/participants`
members were in their REC organization.** The other 35 carried no `organization` claim, so
no org-scoped policy could resolve them to their community. Nothing reconciled what was
true, because nothing read what was true.

**The registry already serves the identical artefact.** `GET /admin/export` returns exactly
the bundle YAML these loaders parse, and with no `community` parameter it returns every
community as a multidocument stream. So this is not a new contract, a new schema or a new
client.

### The defect the switch would have fired

`sync_users` loaded `user_id` for every participant, used it only to decide whether to skip
the row, and then named the account after the member **key** instead:

```python
username = derive_username(key)      # the key, lowercased
```

Against a hand-maintained file that is invisible — the same hand wrote both columns.
Against the registry it is not. `../onboarding` writes `key = submission.ref`
(`20260912-a3f9c2`) and `user_id` = the username Keycloak returned. So the first
registry-backed run would have created a second account named `20260912-a3f9c2` beside the
one the participant already signs in with, once per onboarded participant.

Verified on the dev realm, 2026-09-12, before the repair: `a.person@example.org` and
`a.member@example.org` exist; `20260910-1a2b3c4d` and `20260911-5e6f7a8b` — the keys
their member rows carry — do not. Two duplicates, on the first run.

## Decision

**The registry row is authoritative for the username.** `sync-users` provisions
`p["user_id"]` and derives nothing. `Member.user_id` is a Keycloak *username* — every
self-service route in the registry matches it against the token's `preferred_username` —
so the row that owns the value is what names the account. `derive_username(key)` survives
only as the fallback for a row carrying no `user_id`, which the registry cannot produce
(the column is non-nullable) and only a hand-authored seed file has.

The two conventions are **not converged**, and do not need to be. The username is a
**static handle the participant neither chooses nor changes** — it is what an account is
matched by, with email as a fallback where a lookup offers one. Its shape therefore carries
no meaning: `gl-00001` from a seed and `a.person@example.org` from onboarding are equally
correct, and the second is **not an email** — it is a string onboarding happened to take
from one, and it would still be the username if that convention changed tomorrow.

**So nothing may parse, normalise or infer from it.** The only correct operation on a
`user_id` is to use it verbatim. What matters is that neither writer is guessing.

**Dual source, one parser.** The positional path keeps working and is not deprecated —
bootstrap runs before the registry holds anything, and an offline run is real.
`--from-registry` / `--registry-url` selects the live source. The three loaders take a
parsed document instead of a `Path`, so **nothing below them can tell which source it
got**; that indistinguishability is the property to keep, because the moment the two
sources produce different plans this is two code paths wearing one name.

**Only `active` members are provisioned.** The bundle carries `status`, mandatory in the
registry's schema, and `pending` / `suspended` / `inactive` are not people who should be
handed a login. A row with no `status` is treated as active: hand-authored files predate
the field, and reading absent as pending would have stopped provisioning every seed REC.
Nothing is disabled — skipping provisioning and revoking access are different acts with
different owners, and this command has never written `enabled: false`.

**A run with no community named reconciles every community.** The tenant list comes from
the registry in the same artefact as the members, which is what makes a scheduled reconcile
possible without a list of REC slugs maintained somewhere else. `--community` narrows it,
and a name the source does not hold is refused rather than ignored — a typo that reconciles
nothing while reporting success would make the run that was supposed to catch drift the
thing that hides it. The realm-level work — claim scopes, realm groups, the oauth2-proxy
audience mapper — runs once per run, not once per community.

**`--check` reports divergence and writes nothing.** It walks the source and asks whether
Keycloak agrees: no account, outside the REC organization, outside a declared
`admin_permissions` group. It creates nothing, including a missing organization, which is
reported once for the community rather than once per member.

## The registry is read as `celine-cli`, which is wider than this needs

`celine-cli` already holds `rec-registry.admin` and `aud: svc-rec-registry`, so nothing in
`clients.yaml` changes. **That scope is wider than `rec-registry.export` in a direction
that matters:** through the SDK's admin override it also satisfies `rec-registry.import` —
a replacement import that deletes a community with every member and asset in it — and
`rec-registry.members.purge`. The credential this command carries is therefore capable of
destroying the registry it reads.

This was chosen deliberately, over a client declaring `rec-registry.export` alone, and the
cost is recorded here rather than mitigated in the realm. Two things keep it honest, and
both are load-bearing:

- **`export_communities` is the only registry method named anywhere in this repository.**
  `src/celine/policies/cli/keycloak/registry.py` imports one method and
  `tests/test_registry_source.py` fails if a second is touched.
- **The client id is configurable** — `--registry-client-id`,
  `CELINE_SYNC_USERS_REGISTRY_CLIENT_ID` — and the secret lookup follows it. Declaring a
  client with `rec-registry.export` alone and pointing the flag at it needs no code change.

If the narrow client is ever declared, this section is what should be deleted.

## Consequences

**A member provisioned from the registry path has no email on their Keycloak account.**
`Member` has no email column and this change adds none. That is the state today outside
`--mock`, and it is acceptable while onboarding is what provisions people who need one —
but it is the constraint any future "the registry drives provisioning entirely" design has
to answer first.

**`--mock` no longer appends a domain to a value that already contains one.** The test is
on the string and not on what it means: `f"{username}@celine.localhost"` produced
`a.person@example.org@celine.localhost`, which Keycloak accepts and nobody can receive
mail at.

**A row with no `user_id` is no longer skipped.** It used to be dropped with a warning,
which silently excluded exactly the seed members the file path exists to provision. The
warning survives.

**`keycloak sync` is unchanged.** Realm structure — clients, scopes, audiences, admin
permissions — stays declaration-driven from `clients.yaml`. Only membership moves.

**This does not make `sync-users` a service.** Every part of it is equally useful to a CLI
and to a reconciler with no ingress, and the registry-reading half is what such a service
would need first. If that is chosen, this is the code it is built from.
