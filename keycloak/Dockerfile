FROM quay.io/keycloak/keycloak:26.6.0

# Copy custom theme
COPY themes/rec /opt/keycloak/themes/rec

# Pre-build Keycloak for faster startup
RUN /opt/keycloak/bin/kc.sh build

# Footer link env vars (optional — links are hidden when unset)
# TERMS_URL=https://example.com/terms
# PRIVACY_URL=https://example.com/privacy

USER 1000