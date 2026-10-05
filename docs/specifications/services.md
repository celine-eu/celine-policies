# Service surface

What both HTTP services of this repository — the MQTT auth backend (`celine.mqtt_auth`) and the
provisioning service (`celine.provisioning`) — expose beyond their routes, and what they record
when they refuse a caller.

The posture signal is the platform's (`celine.sdk.posture`): `CELINE_ENV`, then `ENVIRONMENT`;
**only `dev` relaxes**.

---

### REQ-0018 — outside dev, the API docs are not served

`/docs` (Swagger UI), `/redoc` and `/openapi.json` answer `404` in a hardened environment
(`celine.sdk.posture.docs_urls`). They are served in `dev`, and outside dev only when
`CELINE_PUBLIC_DOCS=true` (also `1`, `yes`, `on`).

`create_app().openapi()` still builds the document in-process in every environment, so a
contract test or a client generator that imports the app is unaffected.

> Until 2026-10 both services served all three in every environment (NIS2 review finding R30).

### REQ-0019 — a refusal is one audit record naming the caller, and no log line carries a claim

Every refusal of a request that presented a token is one record on the `celine.audit` logger
(`celine.sdk.audit.audit_denied`, `WARNING`, one JSON object per line). It carries the caller's
`sub` and client id (`azp`) when the token verified, and `null` for both when it did not: an
unverified token names nobody. No other claim is written, by the audit record or by any other
log line, at any level — no email, name, username, scope list or policy input.

| Service | Refusal | `action` | `resource` | `reason` |
|---|---|---|---|---|
| MQTT auth | `/user` with a token that does not verify | `mqtt.connect` | — | `invalid_token` |
| MQTT auth | `/acl` with a token that does not verify | `mqtt.acl` | the topic | `invalid_token` |
| MQTT auth | `/acl` with an `acc` mask carrying no known verb | `mqtt.acl` | the topic | `invalid_acc_mask` |
| MQTT auth | `/acl` denied by the policy | `mqtt.<verb>` (`subscribe`, `publish`, `read`) | the topic | the policy's reason |
| MQTT auth | `/acl` whose evaluation failed | `mqtt.<verb>` | the topic | `check_failed` |
| provisioning | `401 invalid_token` | the route's action | the community | `invalid_token` |
| provisioning | `403 insufficient_scope` | the route's action | the community | `insufficient_scope` |

The provisioning actions are `participant.upsert`, `participant.update`, `participant.invite`,
`participant.disable` and `community.reconcile`. The member key is not recorded; the route
template (`/participants/{community}/{key}`) is.

Not recorded:

- **a request with no token** (`/user`, `/acl`, provisioning's `401 missing_token`): it names
  nobody;
- **an allowed MQTT ACL check**: the broker asks for every publish and subscribe, so an allow
  leaves at most a `DEBUG` line with the topic and verbs;
- **`/superuser`**, which refuses every request (REQ-0014) and is not an authorization decision
  about any topic.

> Until 2026-10 an MQTT ACL denial logged the whole policy input, every claim of the token
> included, and every allowed check was an `INFO` line naming the caller (NIS2 review finding R31).
