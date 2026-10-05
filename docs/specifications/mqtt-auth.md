# MQTT auth

The `celine.mqtt_auth` backend that mosquitto-go-auth calls (`/user`, `/acl`, `/superuser`).
Behaviour is described in [mqtt-integration.md](../mqtt-integration.md); these are the parts a
deployment's posture decides.

The posture signal is the platform's (`celine.sdk.posture`): `CELINE_ENV`, then `ENVIRONMENT`;
**only `dev` relaxes** — unset, `prod`, `staging`, `test`, `local`, `ci` or a typo is hardened.

---

### REQ-0009 — outside dev, startup refuses an MQTT auth service with no token audience or the SDK's local OIDC defaults

`create_app` runs the posture guard before it loads a policy. In a hardened environment it
raises `InsecureConfiguration`, listing every violation at once, when:

- `CELINE_OIDC_AUDIENCE` is not set — without it a token issued to **any** client of the realm
  is accepted as an MQTT credential;
- `CELINE_OIDC_BASE_URL` or `CELINE_OIDC_JWKS_URI` was not set and the SDK's local-Keycloak
  default is in use.

`CELINE_OIDC_AUDIENCE` is read from the environment and, when set, enforced on every token in
every environment: a token whose `aud` does not contain it is answered `403`. In `dev` the
audience is optional and the findings above are logged as one warning.

> Until 2026-10 the service constructed its OIDC settings with `audience=None`, overriding the
> environment, so no audience was ever checked (NIS2 review finding R24).

### REQ-0010 — the service answers no cross-origin request

The service installs no CORS middleware, in any environment: its callers are mosquitto-go-auth's
HTTP backend and health probes, never a browser. A preflight gets no
`Access-Control-Allow-Origin`, and neither does any other response.

> Until 2026-10 `dev` answered cross-origin requests from any origin, with credentials (NIS2
> review finding R31).

### REQ-0014 — no MQTT superuser, no group grant, and a service is what its token says it is

The MQTT auth backend under the two-level model ([REQ-0011](keycloak-cli.md)):

- **`/superuser` always answers `403`**, for every token: no scope, group or role makes a
  client an MQTT superuser. A realm `platform-admin` is not one either.
- **User or service is decided by the token's kind** (`celine-sdk`'s `is_service_account`),
  never by whether the token holds a group. A service account is judged by its scopes; a
  person's token is a user whatever scopes it carries.
- **No group grants anything on the broker.** The policy input carries no groups at all: no
  realm `groups`, no organization group, no merge of the two. A group named like a grant
  (`admin`, `mqtt.admin`, `<service>.admin`, `<service>.<resource>.<verb>`) in either place is
  inert.
- **A platform role grants nothing on the broker either.** `platform-admin` is not an MQTT
  grant, and no role reaches the policy through `groups`.

A person's token therefore reaches no topic: the broker's clients are services, each holding
its declared `<service>.<resource>.<verb>` scopes.

### REQ-0017 — a broker token is a token requested for the broker

`CELINE_OIDC_AUDIENCE` (REQ-0009) is `svc-mqtt`, and only a token **requested with the scope
`mqtt`** carries it:

- `clients.yaml` declares the scope `mqtt` with `audience: svc-mqtt`; `sync` keeps one audience
  mapper (`included.custom.audience`) on that client scope. The scope grants nothing — topic
  access is still the token's `<service>.<resource>.<verb>` and `<service>.admin` scopes.
- `broker_scope: mqtt` makes `sync` grant it as an **optional** scope to every service-account
  client holding a scope the ACL can grant a topic with. Nobody lists it by hand, and a browser
  client never gets it.
- celine-sdk's `MqttBroker` asks its client-credentials provider for `scope=mqtt`
  (`MqttConfig.token_scope`). Tokens a service mints for HTTP calls do not carry `svc-mqtt`,
  so a service that receives another service's token cannot replay it to the broker.

> Before 2026-10 the deployed broker required `svc-celine-policies`, an audience no client's
> token carried, so every MQTT client was refused outside dev (NIS2 review finding R24).
