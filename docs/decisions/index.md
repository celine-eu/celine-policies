# Decisions

Architecture decision records: **why a technical choice was made here**, when the reason
is not derivable from the code and would otherwise be re-litigated.

One file per decision, named `ADR-####-short-slug.md`, with this shape:

```markdown
# ADR-0001 — <the decision, as a statement>

**Date:** <ISO-8601>
**Status:** accepted | superseded by ADR-####

## Context
<what forced a choice. The constraint, and what had already been tried.>

## Decision
<what was decided, in the imperative.>

## Consequences
<what this costs, what it forecloses, and what will tempt someone to undo it.>
```

## What is not an ADR

- **A requirement.** What the product must do belongs with the requirements, where it can
  be traced to a test. An ADR is measured by nothing.
- **A rule with a referent that something already measures.** If a statement could carry
  an identifier and a test that names it, put it where that measurement happens. Deciding
  it here hides it from the report.
- **A procedure.** That is a playbook, and playbooks live in the companion.
- **A fact about the code.** That is knowledge, and knowledge lives in the companion.

An ADR is immutable once accepted. It is superseded by a later ADR that names it, never
edited to say something else.

## The records

| ADR | Decision |
|---|---|
| [ADR-0001](ADR-0001-merge-in-the-loader.md) | A realm declared by several files is merged in the loader, not pre-merged into a file |
| [ADR-0002](ADR-0002-undefined-scope-grants-are-fatal.md) | A grant naming a scope no file declares stops the sync before it starts |
| [ADR-0003](ADR-0003-declare-realm-administration-as-a-group-scoped-permission.md) | A service account's realm administration is declared, and scoped to one group — *superseded by ADR-0007* |
| [ADR-0004](ADR-0004-a-group-grant-carries-view-and-belongs-to-one-client.md) | A group grant carries `view`, and a group belongs to one client |
| [ADR-0005](ADR-0005-sync-users-files-participants-in-the-administered-group.md) | `sync-users` files participants in the group the declaration administers — *superseded by ADR-0007* |
| [ADR-0006](ADR-0006-the-registry-is-the-source-of-members.md) | The REC registry is the source of members, and a YAML file is a seed |
| [ADR-0007](ADR-0007-realm-wide-administration-is-declared-for-a-holder-with-no-public-route.md) | Realm-wide administration is declarable, for a holder with no public route |
| [ADR-0008](ADR-0008-each-cli-command-owns-one-level-of-the-realm.md) | Each CLI command owns one level of the realm, and checks the levels below it; `bootstrap` owns the platform level (supersedes ADR-0003's enabling of admin permissions by `sync`) |
| [ADR-0009](ADR-0009-what-the-realm-import-carried-is-declared.md) | What the realm import carried is declared: `oauth2_proxy` in `clients.yaml`, the operator realm admin in `bootstrap`, the dev users in `seed-dev-users` |
