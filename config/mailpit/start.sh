#!/bin/sh
# Mailpit for the local stack: it keeps every message Keycloak sends in its UI
# (http://localhost:8025) and delivers none of them, unless both of these are set:
#
#   EMAIL_DEV_RECIPIENTS  comma-separated addresses that may receive real mail
#   MAILPIT_RELAY_HOST    the SMTP server to relay them to (MAILPIT_RELAY_PORT,
#                         default 587; MAILPIT_RELAY_USERNAME/PASSWORD if needed)
#
# Then only an address on the list is relayed. The match is built anchored and
# with every address escaped, because an unescaped `.` or a missing `$` widens
# who gets real mail (measured, a-participant-is-invited-and-sets-their-own-password,
# Phase 1). The provisioning service reads the same EMAIL_DEV_RECIPIENTS.
set -eu

set -- --smtp-auth-accept-any --smtp-auth-allow-insecure

if [ -n "${EMAIL_DEV_RECIPIENTS:-}" ] && [ -n "${MAILPIT_RELAY_HOST:-}" ]; then
  pattern=""
  for address in $(printf '%s' "$EMAIL_DEV_RECIPIENTS" | tr ',' ' '); do
    escaped=$(printf '%s' "$address" | sed 's/[][\.*^$()+?{}|\\/]/\\&/g')
    pattern="${pattern:+$pattern|}$escaped"
  done
  if [ -n "$pattern" ]; then
    {
      echo "host: ${MAILPIT_RELAY_HOST}"
      echo "port: ${MAILPIT_RELAY_PORT:-587}"
      if [ -n "${MAILPIT_RELAY_USERNAME:-}" ]; then
        echo "auth: plain"
        echo "username: ${MAILPIT_RELAY_USERNAME}"
        echo "password: ${MAILPIT_RELAY_PASSWORD:-}"
      fi
    } > /tmp/relay.yaml
    set -- "$@" --smtp-relay-config /tmp/relay.yaml --smtp-relay-matching "^($pattern)\$"
    echo "mailpit: relaying only ^($pattern)\$ to ${MAILPIT_RELAY_HOST}"
  fi
else
  echo "mailpit: no relay; every message is kept here and none is delivered"
fi

exec /mailpit "$@"
