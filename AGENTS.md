## Repository role

This repo contains parts related to authentication and authorization.

## Structure

`src/celine/mqtt_auth` is a fastapi `mosquitto_auth` JWT check endpoint to control patterns withing a topic. See also `policies`. 
The pattern for MQTT topic follow a `celine/service/action` model eg. `celine/pipelines/runs/+`.

`src/celine/policies` is a CLI tool with those commands

- `keycloak bootstrap` perform an admin-cli login and stores local credentials for reuse
- `keycloak sync` takes a `./clients.yaml` clients/scopes definition and create the corresponding clients with scopes in KC
- `keycloak sync-users` takes a `rec-registry` REC definition yaml and insert KC users and organizations (REC, DSO)
- `keycloak sync-orgs` takes a governance-bound `owners.yaml` (schema `celine-utils/schema/owners.schema.json`) and create organizations in KC

`./keycloak` contains the custom theme for keycloak. It also provides a `version.txt` that tracks the KC version and theme version eg `26.6.0-1.0.3`. A github pipeline detect changes to version files and publish an update.