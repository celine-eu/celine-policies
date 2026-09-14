# API Reference

HTTP endpoints exposed by this repository's two services — the MQTT auth service
(`celine.mqtt_auth`) and the provisioning service (`celine.provisioning`).

## Base URL

| Service | Environment | URL |
|---|---|---|
| MQTT auth | Development | `http://localhost:8009` |
| MQTT auth | Docker Compose | `http://mqtt_auth:8009` |
| Provisioning | Docker Compose | `http://provisioning:8010` |

**The provisioning service has no public URL and must not be given one.** It is reachable
only from inside the network; see
[ADR-0007](decisions/ADR-0007-realm-wide-administration-is-declared-for-a-holder-with-no-public-route.md).

## Authentication

All endpoints (except `/health`) require a JWT in the `Authorization` header:

```
Authorization: Bearer <jwt-token>
```

The JWT is validated using the OIDC configuration from `celine-sdk` (`OidcSettings`).

---

## POST /user

Authenticate an MQTT client. Called by mosquitto-go-auth on client connect.

Extracts the JWT from the `Authorization` header, validates it, and returns success if the token is valid.

**Response (200):**

```json
{"ok": true, "reason": "authenticated"}
```

**Response (403):**

```json
{"ok": false, "reason": "missing token"}
```

```json
{"ok": false, "reason": "invalid credentials"}
```

---

## POST /acl

Authorize MQTT topic access. Called by mosquitto-go-auth on every publish/subscribe.

Validates the JWT, converts the mosquitto `acc` bitmask to action names, and evaluates the `celine.mqtt.acl` Rego policy for each action.

**Request Body (JSON):**

```json
{
  "clientid": "my-client",
  "topic": "celine/digital-twin/events/pump/pump-001",
  "acc": 2
}
```

| Field | Type | Description |
|-------|------|-------------|
| `clientid` | string | MQTT client ID |
| `topic` | string | MQTT topic being accessed |
| `acc` | int | Access bitmask: 1=read, 2=publish, 4=subscribe |

**Access bitmask values:**

| Value | Permission |
|-------|------------|
| 1 | Read |
| 2 | Publish |
| 4 | Subscribe |
| 3 | Read + Publish |
| 5 | Read + Subscribe |
| 7 | All |

**Response (200):**

```json
{"ok": true, "reason": "authorized"}
```

**Response (403):**

```json
{"ok": false, "reason": "denied"}
```

---

## POST /superuser

Check if a client has MQTT superuser access. Superusers bypass all ACL checks.

Grants superuser if the JWT contains:
- The `mqtt.admin` scope, OR
- The `admin` group, OR
- The `mqtt.admin` group

**Request Body (JSON):**

```json
{
  "username": "client-id-or-jwt"
}
```

**Response (200):**

```json
{"ok": true, "reason": "superuser"}
```

**Response (403):**

```json
{"ok": false, "reason": "not superuser"}
```

---

## GET /health

Liveness check. No authentication required.

**Response:**

```json
{
  "status": "healthy",
  "policies_loaded": true,
  "policy_count": 2,
  "packages": ["celine.mqtt.acl", "celine.scopes"]
}
```

---

## GET /docs

Swagger UI for interactive API exploration.

## GET /redoc

ReDoc API documentation.

---

## Error Responses

| Code | Meaning |
|------|---------|
| 200 | OK (check `ok` field for auth result) |
| 403 | Authentication/authorization failed |
| 500 | Internal error (e.g. policy parse failure) |

The MQTT auth endpoints always return a `MqttResponse` body with `ok` and `reason` fields. HTTP status 403 is set alongside `ok: false` to satisfy mosquitto-go-auth's expected behavior.

---

# Provisioning service

`celine.provisioning` — the only thing that writes a participant account into the celine
realm. Stateless: a retry is another call, and idempotency comes from the keys.

## Authentication

A bearer token, as everywhere else. A token that does not verify is `401`; a token without
the scope is `403`. `provisioning.admin` satisfies any of the scopes below.

| Endpoint | Scope |
|---|---|
| `PUT /participants/{community}/{key}` | `provisioning.participants.write` |
| `POST /participants/{community}/{key}/invitation` | `provisioning.participants.write` |
| `POST /participants/{community}/{key}/disable` | `provisioning.participants.write` |
| `POST /reconcile/{community}` | `provisioning.reconcile` |

Scope checks are **not** what keeps this service safe — its lack of a route is. The scope
check is defence in depth, for a caller already inside the network.

**`svc-onboarding` is the only client granted a `provisioning.*` scope.** Onboarding is the
single point of access to this service; see
[scopes-and-permissions.md](scopes-and-permissions.md#provisioning).

## PUT /participants/{community}/{key}

Ensure the account exists, is in the REC organization, and is in its org group.

**Request:**

```json
{
  "email": "a.person@example.org",
  "first_name": "A",
  "last_name": "Person",
  "locale": "it",
  "invite": true
}
```

| Field | Required | Meaning |
|---|---|---|
| `email` | yes | Finds the account, or names a new one |
| `first_name`, `last_name` | no | Written on a new account. **Pass both**: an account without them meets Keycloak's "update your profile" form after setting its password (measured on 26.7.3) |
| `locale` | no | `it`, `en` or `es`; anything else is `422`. The language of Keycloak's emails. Written on a new account, and on an existing one only if it has none |
| `invite` | no, default `false` | Have Keycloak email an **invitation** to set a password, **only** if the account was created in this call or has no password. Never a reset: that is `POST …/invitation` with intent `password_reset` |

The address **transits and is stored nowhere** — not in this service, which keeps no
state, and not in the registry, which has no email column. It is on the Keycloak account,
which is where an address somebody logs in with belongs.

**Response (200):**

```json
{
  "user_id": "3f1c…",
  "username": "a.person@example.org",
  "created": true,
  "invitation": "sent",
  "invited": true
}
```

`user_id` is the **Keycloak uuid**, which `../onboarding` needs for its dataspace step.
`username` is what the account authenticates as, **read back from Keycloak** rather than
computed — an account that already existed may authenticate under a convention nobody here
chose — and it is the value that becomes the registry's `Member.user_id`. Note the name
collision: the registry's `user_id` column holds a *username*.

Always `200`. A create and a no-op are the same request with the same meaning; `created`
says which happened.

**`invite` never fails the upsert.** What happened is in `invitation`, a reason code to show
the operator who approved, and `invited` is true only for `sent`:

| `invitation` | Meaning |
|---|---|
| `not_requested` | `invite` was false |
| `sent` | Keycloak was asked to email an invitation: `UPDATE_PASSWORD` + `VERIFY_EMAIL`, valid `CELINE_PROVISIONING_INVITE_LIFESPAN` (7 days) |
| `has_password` | The account already has a password; nothing was sent. A retry after the person set their password lands here |
| `no_email` | The account has no email address, in every email mode; nothing was sent. Keycloak sends to the account's own address, so the body's `email` does not stand in for it. Typically an account `sync-users` made from the registry |
| `not_on_dev_list` | `CELINE_PROVISIONING_EMAIL_MODE=dev` and the address is not on `EMAIL_DEV_RECIPIENTS`; a `WARNING` names the member |
| `account_disabled` | The account is disabled; nothing was sent, and it is not re-enabled |
| `cooldown` | The account was emailed within `CELINE_PROVISIONING_INVITE_COOLDOWN`, by an upsert or by `…/invitation`; nothing was sent. Ask again after the cooldown |
| `send_failed` | Keycloak was asked and did not send it — an SMTP failure (Keycloak's `500 Failed to send execute actions email`), a refusal such as an unregistered redirect URI, or a timeout. **No cooldown starts**, so a retry may send. The upsert itself succeeded |

New codes may be added. A consumer shows an unknown one raw rather than failing on it.

The checks run in this order, and the first that applies is the answer: `account_disabled`,
`has_password`, `no_email`, `not_on_dev_list`, `cooldown`, then the send (`sent` or
`send_failed`).

**One send rule for the upsert and the route:** an email goes out only because a caller asked
(`invite: true` here, or `POST …/invitation`); every send is refused within the cooldown of the
last successful one to that account, whichever call made it; a send that failed starts no
cooldown; an account with a password is never invited, and one without is never sent a
reset; and an account with no email address is never sent anything. So a repeat of the
upsert **before** the person has set a password sends another invitation only once the
cooldown has passed. Every link sent stays usable until it expires, even after another one
has been used (measured on 26.7.3).

**Order of deployment:** `locale` is kept only on a realm with
`internationalizationEnabled`. On a realm without it Keycloak answers `201` and drops the
value, so internationalization has to be enabled on a realm before this service writes
`locale` to it.

Completing an invitation creates **no session**: the person sees Keycloak's "account
updated" page with a link back to `CELINE_PROVISIONING_INVITE_REDIRECT_URI`, and then signs
in once with the password they chose.

**The registry is not written from here.** The caller writes the member row, with the
username this call returned — which keeps the registry single-writer and the step order
fail-closed: the login exists before the row that keys on it.

## POST /participants/{community}/{key}/invitation

Email a member an invitation or a password reset, **as the caller names it**. The member is
resolved through the registry, whose `Member.user_id` is the username. **No password is
generated or returned**: Keycloak sends the link and the person chooses their own.

**Request (required):**

```json
{"intent": "invitation"}
```

The caller names the email, and the service checks it against the account in the same call
that sends. A mismatch is refused **before any send and before the cooldown**, and is never
turned into the other email, so the email is always the button a person pressed:

| `intent` | Account must | `actions` | `lifespan` | Otherwise |
|---|---|---|---|---|
| `invitation` | have no password | `UPDATE_PASSWORD`, `VERIFY_EMAIL` | `CELINE_PROVISIONING_INVITE_LIFESPAN`, default 604800 (7 days) | `409 has_password` |
| `password_reset` | have a password | `UPDATE_PASSWORD` | `CELINE_PROVISIONING_RESET_LIFESPAN`, default 3600 (1 hour) | `409 no_password` |

A missing body, or an `intent` other than these two, is `422`. A reset is short because
Keycloak does not revoke earlier links: a reset email must not be a week-long credential.

**Response (200):**

```json
{
  "user_id": "3f1c…",
  "username": "gl-00001",
  "invitation": "sent",
  "actions": ["UPDATE_PASSWORD", "VERIFY_EMAIL"],
  "lifespan": 604800
}
```

`invitation` is `sent`, or `not_on_dev_list` when dev email mode refused the address (nothing
was sent).

The checks run in this order, and the first that applies is the answer: `community_not_found`,
`member_not_found`, `account_not_found`, `account_disabled`, `has_password` / `no_password`,
`no_email`, `not_on_dev_list` (a `200`), `cooldown`, then the send (`sent` or `send_failed`).

| Status | `code` | Meaning |
|---|---|---|
| 404 | `community_not_found` | The registry has no community under `{community}` |
| 404 | `member_not_found` | The community has no **active** member under `{key}` |
| 404 | `account_not_found` | The registry has the member, and the realm has no account for it. Provision it first |
| 409 | `account_disabled` | The account is disabled. Checked by this service before Keycloak is asked |
| 409 | `has_password` | Intent `invitation`, and the account already has a password. Nothing sent, no cooldown: send `password_reset` instead |
| 409 | `no_password` | Intent `password_reset`, and the account has no password. Nothing sent, no cooldown: send `invitation` instead |
| 409 | `no_email` | The account has no email address, in every email mode. Nothing sent |
| 422 | — | No body, or an unknown `intent` |
| 429 | `cooldown` | The same account was emailed within `CELINE_PROVISIONING_INVITE_COOLDOWN` (default 300 s), by this route or by an upsert. `Retry-After` says when. In memory and per replica: a double-click guard, not a rate limit |
| 502 | `send_failed` | Keycloak did not send it. No cooldown starts, so a retry may send |

## POST /participants/{community}/{key}/disable

Revoke access. The account, its memberships and everything keyed on its uuid survive —
disabling is not deletion, and reversing it is one call.

**Response (200):**

```json
{"user_id": "3f1c…", "username": "gl-00001", "changed": true}
```

`changed: false` means the revocation was already in force, which must not read as one
that just happened.

`404` with `community_not_found`, `member_not_found` or `account_not_found`, as for the
invitation.

## POST /reconcile/{community}

Provision every **active** member the registry holds for one community, then assert that
each of them is in the REC's organization. Members that are not active are skipped and not
disabled — skipping provisioning and revoking access are different acts.

**Response (200):**

```json
{"community": "greenland", "members": 45, "created": 2, "existing": 43, "divergences": []}
```

**Response (500)** when the assertion finds anything: the same body, under `detail`, with
the divergences listed, and `code: "reconcile_diverged"` and a `message` beside them.
`404` `community_not_found` for a community the registry does not have. Everything checked is something this same call claimed to have
done, so a finding is a provisioning call that reported success and had not succeeded. It
fails loudly rather than repairing quietly — a `200` with a list nobody reads is how 10 of
45 members ended up outside their own organization with nothing saying so.

What calls this on a schedule is a deployment concern. The route is an entry point and
nothing here is a scheduler.

## Error responses

Every error but `422` has one body:

```json
{"detail": {"code": "member_not_found", "message": "greenland has no active member 'gl-00099'"}}
```

`code` is stable and machine-readable; branch on it. `message` is a sentence for a person
and not a contract. `code` is a plain string in the OpenAPI document, not an enum, so a code
added later does not break a generated client: treat an unknown one by its status. `422` is
FastAPI's own validation body, `{"detail": [ … ]}`.

| Status | `code` | Meaning |
|---|---|---|
| 401 | `missing_token` | No bearer token — send one |
| 401 | `invalid_token` | It does not verify — renew the credential |
| 403 | `insufficient_scope` | Verified, but the caller does not hold the scope — ask for a grant |
| 404 | `community_not_found` | The registry has no such community |
| 404 | `member_not_found` | The community has no active member under that key |
| 404 | `account_not_found` | The member exists, and the realm has no account for it |
| 409 | `account_disabled` | An invitation for a disabled account |
| 409 | `has_password` | Intent `invitation` for an account that has a password |
| 409 | `no_password` | Intent `password_reset` for an account that has none |
| 409 | `no_email` | A send to an account with no email address |
| 422 | — | The upsert's body is missing the address, or `locale` is not `it`, `en` or `es`; the invitation's body is missing, or its `intent` is unknown |
| 429 | `cooldown` | An invitation within the cooldown; `Retry-After` says when |
| 500 | `reconcile_diverged` | A reconcile ended with divergences; the report is in `detail` |
| 502 | `registry_unavailable` | The registry could not be read, or is not configured |
| 502 | `send_failed` | Keycloak did not send the email: SMTP failure, a refusal such as `Invalid redirect uri.` for a `CELINE_PROVISIONING_INVITE_REDIRECT_URI` not registered on `oauth2_proxy`, or a timeout. Starts no cooldown |
| 502 | `provisioning_failed` | Any other dependency failure — a dependency, not this service refusing |

A registry `404` counts as `community_not_found` only when the registry names the community.
Its unrouted `{"detail": "Not Found"}` — a wrong `CELINE_PROVISIONING_REGISTRY_URL` — stays
`registry_unavailable`, because a consumer may read a `404` as "nothing left to do".

## Configuration

`CELINE_PROVISIONING_*`, besides the registry and OIDC settings:

| Variable | Default | Meaning |
|---|---|---|
| `CELINE_PROVISIONING_INVITE_REDIRECT_URI` | unset | Where "back to the application" points after an invitation or reset: the webapp root. Must be registered on the client below. Unset, the final page has no link back |
| `CELINE_PROVISIONING_INVITE_CLIENT_ID` | `oauth2_proxy` | The client the redirect is registered on |
| `CELINE_PROVISIONING_INVITE_LIFESPAN` | `604800` | Seconds an invitation link lasts |
| `CELINE_PROVISIONING_RESET_LIFESPAN` | `3600` | Seconds an operator reset link lasts |
| `CELINE_PROVISIONING_INVITE_COOLDOWN` | `300` | Seconds after a successful send during which any further send to that account is refused: `429` on `…/invitation`, `invitation: cooldown` on the upsert. `0` disables it |
| `CELINE_PROVISIONING_EMAIL_MODE` | `dev` | `deliver` emails anyone; `dev` emails only `EMAIL_DEV_RECIPIENTS` and logs a `WARNING` for everyone else |
| `EMAIL_DEV_RECIPIENTS` | empty | Comma-separated addresses that may be emailed in `dev` mode. Also read as `CELINE_PROVISIONING_EMAIL_DEV_RECIPIENTS`. The local Mailpit relays the same list |

`dev` is the default on purpose: its failure is an invitation that did not go out and says
so. Every non-dev deployment sets `deliver`.
