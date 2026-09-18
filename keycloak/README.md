# Keycloak

Custom Keycloak image for CELINE, bundling the `rec` login and email themes.

Current version: `26.7.3-1.1.0` (format: `<keycloak-version>-<theme-version>`, tracked in `version.txt`).

## Docker image

The `Dockerfile` extends the official Keycloak 26.7.3 image, copies the theme, and runs `kc.sh build` at image-build time for faster container startup.

```bash
docker build -t celine-keycloak .
docker run -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
           -e BRAND_NAME="My Community" \
           -e TERMS_URL=https://example.com/terms \
           -e PRIVACY_URL=https://example.com/privacy \
           -p 8080:8080 celine-keycloak start-dev
```

### Runtime environment variables

| Variable | Required | Description |
|---|---|---|
| `BRAND_NAME` | No | Logo text on the login page. Defaults to `CELINE`. Overridden by `realm.displayName` if set in Keycloak. |
| `TERMS_URL` | No | URL for the Terms link in the login footer. Hidden when unset. |
| `PRIVACY_URL` | No | URL for the Privacy link in the login footer. Hidden when unset. |

## Theme

The `themes/rec` directory contains a custom login theme matching the REC webapp design system, and an email theme for the three emails a participant receives. See [`themes/README.md`](themes/README.md) for customisation details.

Key behaviours:

- **Logo / realm name** — displays `realm.displayName`, falling back to the `BRAND_NAME` env var (default: `CELINE`). Set either the env var or the display name in Keycloak's realm settings to match the deployed organisation.
- **Social providers** — the "continue with" section is only shown when at least one social/identity provider is configured. It is hidden automatically when none are present.
- **Footer links** — rendered only when `TERMS_URL` / `PRIVACY_URL` are provided. Values are injected via Keycloak's `${env.VAR:default}` substitution in `theme.properties`.
- **Internationalisation** — Italian, English and Spanish (`it`, `en`, `es`), in both themes. `test_keycloak_theme_messages.py` fails when a key a template uses is missing from a bundle.
- **`info.ftl` resolves its header through `msg()`** — `messageHeader` is a message key. Printed raw, the page every invitation and reset ends on showed `accountUpdatedTitle` as its title.
- **Passkeys** — when the realm enables them, `login.ftl` shows "Sign in with Passkey" and the browser offers a passkey from the username field (`autocomplete="username webauthn"`). `template.ftl` carries the import map Keycloak's WebAuthn scripts need (`rfc4648`); without it, passkey registration and sign-in silently do nothing.
- **Pages inherited from Keycloak** — passkey registration, TOTP set-up, recovery codes and the "try another way" list come from the parent theme. `login.css` restyles their PatternFly buttons, the recovery-code list and warning, and keeps a card taller than the screen from overflowing above the top. `test_keycloak_theme_passkeys.py` checks these; `tests/integration/test_imported_realm_login.py` checks the rendered login page.

### Email theme

`themes/rec/email/` (`parent=base`) overrides three emails and inherits the rest:

| Template | Sent for | Wording |
|---|---|---|
| `executeActions.ftl` | the provisioning service's invitation and operator reset | "set your password" when the token's actions include `VERIFY_EMAIL` (an invitation), "reset your password" otherwise. One template, two emails |
| `password-reset.ftl` | forgot password, from the login page | reset |
| `email-verification.ftl` | a verification Keycloak sends | confirm the address |

Each has an `html/` and a `text/` part. The emails name the platform (`realmName`, then
`BRAND_NAME`), not a community. Subjects are fixed keys with no parameters, so
`executeActionsSubject` is worded to fit both uses. Expiry is always
`linkExpirationFormatter(linkExpiration)`: the raw value is minutes. Text templates declare
`output_format="plainText"`, and HTML templates never use `?no_esc` on the model.

The invitation copy ends with "sign in with your new password", because completing an
invitation creates no session: the next page after "back to the application" is the login
form.

### Enabling the theme

In Keycloak Admin Console: **Realm Settings → Themes → Login theme → `rec`**, and **Email theme → `rec`**. The email language is the user's `locale` attribute, which needs **Realm Settings → Localization → Internationalization** on.

## Versioning

`version.txt` tracks `<keycloak-version>-<theme-version>`. The CI pipeline detects changes to this file and publishes an updated image.

