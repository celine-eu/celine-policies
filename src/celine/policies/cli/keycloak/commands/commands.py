"""Keycloak CLI commands.

Commands:
    celine-policies keycloak sync <config.yaml>
    celine-policies keycloak bootstrap
    celine-policies keycloak status
    celine-policies keycloak sync-users [rec_yaml]
    celine-policies keycloak sync-orgs [owners_yaml ...]
"""

import typer

from celine.policies.cli.keycloak.commands.sync import sync
from celine.policies.cli.keycloak.commands.bootstrap import bootstrap
from celine.policies.cli.keycloak.commands.status import status
from celine.policies.cli.keycloak.commands.sync_users import sync_users
from celine.policies.cli.keycloak.commands.sync_orgs import sync_orgs
from celine.policies.cli.keycloak.commands.set_password import set_password

keycloak_app = typer.Typer(
    name="keycloak",
    help="Keycloak management commands",
    add_completion=False,
)

keycloak_app.command("sync")(sync)
keycloak_app.command("bootstrap")(bootstrap)
keycloak_app.command("status")(status)
keycloak_app.command("sync-users")(sync_users)
keycloak_app.command("sync-orgs")(sync_orgs)
keycloak_app.command("set-password")(set_password)
