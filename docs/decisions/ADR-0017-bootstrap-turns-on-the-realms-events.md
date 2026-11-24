# ADR-0017 — `bootstrap` turns on the realm's events, on unless the environment is dev

**Date:** 2026-11-24
**Status:** accepted

## Context

On a non-prod realm the team enters a mirrored member by impersonation (ADR-0015). The
Keycloak `IMPERSONATE` event is the only record of who acted in that member's name. The
platform's security baseline also asks for Keycloak's login and admin events to be on, as the
access audit, kept one year.

On the shared non-prod Keycloak (26.8.1), read on 2026-11-24, the realms had
`eventsEnabled: false` and `adminEventsEnabled: false`. Nothing wrote them: Keycloak creates a
realm with both off, and a hand edit in the console is neither repeatable nor reviewable. The
requester asked that `bootstrap` turn them on, rather than a manual edit.

## Decision

- **`bootstrap` owns the events configuration of the realm it administers** (the platform
  level, ADR-0008), through `GET/PUT /admin/realms/{realm}/events/config`. It never touches
  master's: hardening master stays with ADR-0014, and its events are a separate decision.
- **`CELINE_KEYCLOAK_EVENTS_ENABLED` decides; unset, it is on unless `ENV` is exactly `dev`**,
  the rule brute force and the admin second factor follow. Off leaves the realm's events as
  they are: `bootstrap` never turns recording off.
- **User event types: Keycloak's default set, plus the required ones.** A realm that stores no
  list records every type Keycloak saves by default (sign-in, sign-out, impersonation,
  credential changes; not token refresh, introspection or userinfo, which would flood the
  table), and `GET` reports that set. `IMPERSONATE`, `IMPERSONATE_ERROR`, `LOGIN` and
  `LOGIN_ERROR` are in it, so such a realm is not written a list and keeps following Keycloak's
  defaults across upgrades. A stored list that misses a required type gets it added; nothing is
  removed. An explicit full list was rejected: it would freeze today's defaults, and diff on
  every Keycloak upgrade.
- **User events expire after one year** (`events.expiration`, `31536000` s), the access
  audit's retention, held in Keycloak until a log store keeps the audit. A deployment overrides
  it with `CELINE_KEYCLOAK_PLATFORM_EVENTS_EXPIRATION`, the way it overrides lifespans.
- **Admin event details are off** (`events.admin_details: false`). The details are the request
  representation: a change to a user or a member carries that person's profile. The event
  without them still names who changed which resource, when, from where. Turning them off where
  they are on is destructive and needs `--allow-destructive` outside dev.
- **The listeners are not touched.** `jboss-logging` stays, so events keep reaching the log.
- The tuning lives in `platform.yaml` (`events`), the switch in the environment, as brute force
  splits them. A deployment overlay may not change it.

## Consequences

- **Every realm `bootstrap` administers outside dev records events at its next run**: staging,
  warehouse and prod alike. A deployment that must not (yet) sets
  `CELINE_KEYCLOAK_EVENTS_ENABLED=false` in that job's environment.
- **The write is not partial.** Keycloak sets `eventsEnabled` from the body unconditionally and
  `eventsExpiration` to 0 when it is left out, so every write carries both, and the listeners
  as read (read in the 26.x source; not yet measured on a live realm).
- **It needs `manage-events`/`view-events` in the realm**, which the bootstrap client (master
  `admin`) holds. The admin CLI client does not, and was not widened: a run that signs in as it
  with events on fails on the events call (outside dev that run goes through master anyway).
- **Admin events have no expiry from this change.** Keycloak keeps admin events forever unless
  the realm attribute `adminEventsExpiration` is set; it is a nested realm attribute (read,
  merge, write whole). Whether and how long: da decidere.
