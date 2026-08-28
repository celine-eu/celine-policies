# ADR-0001 — A realm declared by several files is merged in the loader, not pre-merged into a file

**Date:** 2026-08-28
**Status:** accepted

## Context

`keycloak sync` takes one file and recomputes every client's grants from it. That is
correct when one file describes the whole realm, and the celine realm is not one of those:
it carries celine's own services **and** the dataspace services that the `ds` repository
owns. Neither repository can write the other's half, and today the ds half is maintained
here by hand, copied out of a file ds generates for the purpose. On 2026-08-28 that copy
was measured drifting — a client missing entirely while three others named it as an
audience, seven scopes missing, five clients whose grants disagreed in both directions.

Syncing ds's file here instead does not work, because a file describing part of a realm
does not leave the rest alone:

- a client **absent** from the file is an orphan, and orphans are deleted only under
  `--prune`;
- but for every client **present**, the sync diffs the current grants against the desired
  ones and removes the difference, outside the prune branch.

So a partial file does not delete a client — it silently narrows one that stays. `ds` had
already verified this against this CLI and worked around it by pre-merging its own files
into a generated `clients.effective.yaml` (`ir-cli keycloak merge`) before the sync ever
sees them. That workaround exists because this option did not.

## Decision

Merge in the loader, and take the further files as a repeatable `--overlay PATH` on
`keycloak sync`.

Not a `merge` subcommand writing an effective file: a generated intermediate is a third
artefact to keep current, and the failure it introduces — syncing a stale effective file —
is the same class of failure as the drift being fixed.

The merge rule is **ownership, not precedence**. No file is subordinate to another and
there is no last-wins:

- **A client's identity is declared by exactly one file** (`name`, `description`,
  `secret`, `scopes_prefix`, `service_account_enabled`, or any key the model does not
  recognise). A second file declaring any of them is an error naming both files.
- **Any file may add grants** to a client another file declares, by naming `client_id`
  plus `default_scopes` / `optional_scopes` / `extra_audiences` and nothing else.
- **A scope is declared once, or identically more than once.** A conflicting redefinition
  is an error.
- **A realm-level key** may be stated by any file; two files disagreeing is an error.
- **Two clients may not claim one `scopes_prefix`.** The prefix decides which client every
  audience mapper for those scopes points at, and a second claimant silently won.

Interpolation happens once, over the merged document, so that a value substituted into one
file cannot change how another merges into it — and every guard downstream (the
placeholder-secret check, the scope-reference check) sees the whole realm.

A file states what it cannot be synced without (`requires: [ds]`); the file that answers it
identifies itself (`overlay: ds`); a sync missing one fails before authenticating. Matching
is by name because a deployment mounts a file wherever it likes.

## Consequences

**Ownership differs from ds's model deliberately.** ds's merge is core-plus-overlay: the
core owns every client and an overlay may only widen. That is wrong here, because the ds
file is not subordinate — it *owns* the ds clients while this repository owns a few grants
on them. The name `--overlay` is kept for shared vocabulary; the semantics are peers.

**An identical scope redeclaration is accepted, where ds's merge refuses any repeat.** The
two files declare 27 byte-identical scopes today. Refusing outright would make the split a
single flag-day cut; allowing an identical repeat lets a file shed its copies one release
at a time. A *differing* definition is still an error — that is the ambiguity worth failing
on, and two of them exist today.

**Splitting the declaration creates a trap, and the completeness check is what answers it
— not `requires`.** The first design put `requires: [ds]` on `clients.yaml`, reasoning that
once the base file had shed the half another file declares, syncing it alone would strip
those clients back to their host-side grants. That was wrong twice over. **The dataspace is
optional**: a celine deployment without one is ordinary, and a `requires:` on the base file
makes it mandatory. And the binding was never the keyword — grants-only entries for ds
clients bind just as hard, because without ds's file they name clients nobody declares and
the completeness check refuses them regardless.

So the split is by deployment, not by keyword. `clients.yaml` declares celine's services and
nothing about ds; it is a whole realm and syncs alone. `clients.ds-host.yaml` holds the
grants celine adds to ds's clients, is mounted only alongside ds's own file, and is refused
without it by the check that already existed. Neither file carries `requires:`.

`requires:` remains right for a file that genuinely cannot be a realm on its own — ds's
`clients.dataspaces.yaml` is one, and declares `requires: [ds]`. It is a statement that a
file is half a declaration, not a way to pin a deployment topology.

**`from_yaml` stays, and does not enforce completeness.** `sync-orgs` and `sync-users` read
client ids and scopes out of the base file rather than writing a realm, so a declaration
the file needs in order to be *synced* is none of their business. `from_yaml_files(...,
complete=True)` is what asserts these files are the whole realm, and only a caller about to
rewrite one may claim it.

**It makes ds's `ir-cli keycloak merge` redundant.** Its whole justification is this CLI
taking one file. Retiring it is ds's call.
