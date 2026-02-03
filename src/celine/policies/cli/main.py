"""CELINE Policies CLI - Main entrypoint.

Usage:
    celine-policies keycloak sync config.yaml
    celine-policies keycloak bootstrap --admin-user admin --admin-password admin
"""

from __future__ import annotations

import typer

from celine.policies.cli.keycloak.commands import keycloak_app

app = typer.Typer(
    name="celine-policies",
    help="CELINE Policy Service CLI tools",
    add_completion=True,
)

app.add_typer(keycloak_app, name="keycloak")


def create_app() -> None:
    """CLI entrypoint."""
    app()


if __name__ == "__main__":
    create_app()
