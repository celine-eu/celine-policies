# Keycloak

Custom Keycloak image for CELINE, bundling the `rec` login theme.

Current version: `26.6.0-1.0.3` (format: `<keycloak-version>-<theme-version>`, tracked in `version.txt`).

## Docker image

The `Dockerfile` extends the official Keycloak 26.6.0 image, copies the theme, and runs `kc.sh build` at image-build time for faster container startup.

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

The `themes/rec` directory contains a custom login theme matching the REC webapp design system. See [`themes/README.md`](themes/README.md) for customisation details.

Key behaviours:

- **Logo / realm name** — displays `realm.displayName`, falling back to the `BRAND_NAME` env var (default: `CELINE`). Set either the env var or the display name in Keycloak's realm settings to match the deployed organisation.
- **Social providers** — the "continue with" section is only shown when at least one social/identity provider is configured. It is hidden automatically when none are present.
- **Footer links** — rendered only when `TERMS_URL` / `PRIVACY_URL` are provided. Values are injected via Keycloak's `${env.VAR:default}` substitution in `theme.properties`.
- **Internationalisation** — English and Italian (`en`, `it`).

### Enabling the theme

In Keycloak Admin Console: **Realm Settings → Themes → Login theme → `rec`**.

## Versioning

`version.txt` tracks `<keycloak-version>-<theme-version>`. The CI pipeline detects changes to this file and publishes an updated image.

