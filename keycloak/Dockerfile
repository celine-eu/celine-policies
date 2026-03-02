FROM quay.io/keycloak/keycloak:26.4.0

# Copy custom theme
COPY theme/rec /opt/keycloak/themes/rec

# Pre-build Keycloak for faster startup
RUN /opt/keycloak/bin/kc.sh build

USER 1000