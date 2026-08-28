# ADR-0002 — A grant naming a scope no file declares stops the sync before it starts

**Date:** 2026-08-28
**Status:** accepted

## Context

`keycloak sync` checked for grants naming an undeclared scope and printed a yellow warning:

```
Warning: Scopes referenced but not defined: dataset.qeury
```

and then synced. That is not a warning about something harmless. The scope is never
created, so `apply_sync_plan` reaches the assignment, cannot resolve the name, appends
`Scope not found: dataset.qeury` to `result.errors` and the command exits 1 — **after**
every client, scope and mapper before it has already been written. A realm half-rewritten
by a run that then reports failure is worse than either succeeding or refusing.

With one file describing a whole realm this was survivable, because a dangling grant is a
typo the author of that file can see. [ADR-0001](ADR-0001-merge-in-the-loader.md) makes a
realm declarable by several files written by different parties, and then it is not a typo:
it is the ordinary consequence of a grant staying in one file while its scope moves to the
other, or of an `--overlay` nobody passed. It is the specific mistake the split makes
possible, and the one `ds`'s own merge already refused to write a file for.

## Decision

Refuse the sync. `_fail_on_undefined_scopes` runs in `keycloak sync` immediately after the
placeholder-secret guard and, like it, **before authenticating** — so a wrong declaration
fails on the operator's machine rather than halfway through rewriting a live realm. It
names each undeclared scope and the clients that asked for it.

There is no flag and no environment that accepts it. `ENV=dev` buys placeholder secrets
through because a guessable secret on a local realm is a real convenience with a real
scope; a grant naming a scope nobody declares means nothing in any realm.

Keycloak's own scopes (`openid`, `profile`, `email`, `offline_access`, …) are exempt, as
they always were — they are not declared by anyone here because they are not ours.

## Consequences

**A sync that used to run now stops.** Any deployment carrying a dangling grant fails at
the next release instead of writing a realm and then reporting an error. That is the point,
and it is a one-line fix in the file that carries the grant. `clients.yaml` as shipped has
none — asserted by `tests/test_dataspace_scope.py` and again by the merge suite.

**Forgetting `--overlay` is now caught twice.** A base file that declares `requires:` is
refused by that guard; one that does not is usually caught by this one, because the grants
it kept name scopes only the missing file declares. The second is weaker — it fires only if
a grant survived the split — so it does not make `requires:` optional.

**`validate_scope_references` itself is unchanged** and still returns a list. The commands
that only *read* the file (`sync-orgs`, `sync-users`) do not call it, and nothing about
loading a config changed: this is a policy of the command that writes.
