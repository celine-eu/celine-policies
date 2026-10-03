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

### REQ-0010 — CORS is enabled only in dev

In `dev` the service answers cross-origin requests from any origin. In a hardened environment it
installs no CORS middleware: its callers are mosquitto-go-auth's HTTP backend and health probes,
never a browser.
