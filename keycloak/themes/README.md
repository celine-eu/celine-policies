# REC Keycloak Login Theme

A custom Keycloak login theme that matches the REC webapp design system.

## Features

- 🎨 Matches REC webapp styling (colors, typography, spacing)
- 🌙 Automatic dark mode support (via `prefers-color-scheme`)
- 📱 Mobile-first responsive design
- 🌍 Internationalization (Italian, English, Spanish)
- ♿ Accessibility improvements
- 🔐 Custom pages: login, register, password reset, OTP, error

## Installation

### Option 1: Deploy to Keycloak themes directory

1. Copy the `rec` folder to your Keycloak themes directory:
   ```bash
   cp -r rec /opt/keycloak/themes/
   ```

2. Restart Keycloak (or it will auto-detect on next realm config change)

3. In Keycloak Admin Console:
   - Go to **Realm Settings** → **Themes**
   - Set **Login theme** to `rec`
   - Save

### Option 2: Docker / Kubernetes

Mount the theme directory in your container:

```yaml
# docker-compose.yml
services:
  keycloak:
    image: quay.io/keycloak/keycloak:latest
    volumes:
      - ./keycloak-theme/rec:/opt/keycloak/themes/rec:ro
```

Or for Kubernetes:

```yaml
volumes:
  - name: keycloak-theme
    configMap:
      name: rec-keycloak-theme

volumeMounts:
  - name: keycloak-theme
    mountPath: /opt/keycloak/themes/rec
```

### Option 3: Build into Docker image

```dockerfile
FROM quay.io/keycloak/keycloak:latest
COPY keycloak-theme/rec /opt/keycloak/themes/rec
```

## Structure

```
rec/
├── email/
│   ├── theme.properties      # parent=base, locales=it,en,es
│   ├── html/                 # template.ftl (layout), executeActions, password-reset, email-verification
│   ├── text/                 # the same three, plain text
│   └── messages/             # messages_{it,en,es}.properties
└── login/
    ├── theme.properties      # Theme configuration
    ├── template.ftl          # Base HTML template
    ├── login.ftl             # Login page
    ├── register.ftl          # Registration page
    ├── login-reset-password.ftl
    ├── login-update-password.ftl
    ├── login-otp.ftl         # OTP/2FA page
    ├── error.ftl
    ├── info.ftl
    ├── messages/
    │   ├── messages_en.properties
    │   ├── messages_es.properties
    │   └── messages_it.properties
    └── resources/
        ├── css/
        │   └── login.css     # Main stylesheet
        └── img/
            └── (optional logos/favicons)
```

## Customization

### Colors

Edit the CSS variables in `resources/css/login.css`:

```css
:root {
  --color-primary: #0d9488;       /* Teal - main brand color */
  --color-primary-hover: #0f766e;
  --color-bg: #fafbfc;
  /* ... */
}
```

### Logo

The logo is generated via CSS. To use a custom image:

1. Add your logo to `resources/img/logo.png`
2. Update `template.ftl` to reference the image
3. Adjust the CSS in `login.css`

### Messages

Add or modify text in `messages/messages_XX.properties` files.

## Browser Support

- Chrome/Edge 88+
- Firefox 78+
- Safari 14+
- Mobile browsers (iOS Safari, Chrome for Android)

## Dark Mode

The theme automatically switches to dark mode based on the user's system preference (`prefers-color-scheme: dark`). No manual toggle is provided on the login page.

## Accessibility

- Proper focus states
- ARIA labels
- Color contrast meets WCAG AA
- Reduced motion support
- High contrast mode support
