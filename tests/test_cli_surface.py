"""The CLI's command surface, exercised through typer without touching Keycloak.

These are shallow on purpose, and they close a real hole: until now nothing
imported `bootstrap`, `status`, `sync`, `sync_users`, `sync_orgs`,
`set_password` or `set_user_organization` at all. A typo or a stale import in
any of them was a green test run and a `celine-policies keycloak sync` that dies
on startup — which is how the previous suite came to reference three modules
that no longer exist.

Building the app imports every command module; rendering each `--help` walks its
option declarations, so a malformed `Annotated`/`typer.Option` default fails
here rather than in front of an operator.

The command *names* are asserted literally because `taskfile.yaml`, the README
and the deployment docs invoke them as strings — renaming one silently breaks
callers that no import graph connects.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from celine.policies.cli.keycloak.commands.commands import keycloak_app
from celine.policies.cli.main import app

runner = CliRunner()

# Every subcommand of `celine-policies keycloak`, as documented in AGENTS.md and
# driven from taskfile.yaml.
COMMANDS = [
    "sync",
    "bootstrap",
    "status",
    "sync-users",
    "sync-orgs",
    "set-password",
    "set-user-organization",
]


class TestTopLevelApp:
    def test_the_root_help_renders(self):
        result = runner.invoke(app, ["--help"])

        assert result.exit_code == 0
        assert "keycloak" in result.output

    def test_the_keycloak_group_is_mounted(self):
        """The console script is `celine-policies`; `keycloak` is its only group."""
        result = runner.invoke(app, ["keycloak", "--help"])

        assert result.exit_code == 0

    def test_an_unknown_group_fails(self):
        result = runner.invoke(app, ["nonsense"])

        assert result.exit_code != 0

    def test_the_entrypoint_is_importable(self):
        """`pyproject.toml` points the console script at this callable."""
        from celine.policies.cli.main import create_app

        assert callable(create_app)


class TestKeycloakCommands:
    def test_every_documented_command_is_registered(self):
        registered = {
            command.name or command.callback.__name__
            for command in keycloak_app.registered_commands
        }
        assert set(COMMANDS) <= registered

    def test_no_undocumented_commands_have_appeared(self):
        """A new command needs a line in AGENTS.md and this list."""
        registered = {
            command.name or command.callback.__name__
            for command in keycloak_app.registered_commands
        }
        assert registered == set(COMMANDS)

    @pytest.mark.parametrize("command", COMMANDS)
    def test_each_command_help_renders(self, command: str):
        """Imports the module and validates its whole option declaration."""
        result = runner.invoke(app, ["keycloak", command, "--help"])

        assert result.exit_code == 0, result.output

    @pytest.mark.parametrize("command", COMMANDS)
    def test_each_command_documents_itself(self, command: str):
        """`--help` is the only reference an operator has at the terminal."""
        result = runner.invoke(app, ["keycloak", command, "--help"])

        assert "Usage:" in result.output
        assert len(result.output.strip().splitlines()) > 3


class TestSyncOptions:
    """`sync` writes to a realm, so its safety flags are asserted by name."""

    @pytest.fixture
    def help_text(self) -> str:
        return runner.invoke(app, ["keycloak", "sync", "--help"]).output

    def test_dry_run_is_offered(self, help_text: str):
        assert "--dry-run" in help_text

    def test_prune_is_offered(self, help_text: str):
        """Deletion is opt-in; the flag must stay explicit rather than implied."""
        assert "--prune" in help_text

    def test_connection_overrides_are_offered(self, help_text: str):
        for flag in ("--base-url", "--realm"):
            assert flag in help_text, flag

    def test_admin_credential_overrides_are_offered(self, help_text: str):
        """The documented recovery path when a stored client secret is stale."""
        for flag in ("--admin-user", "--admin-password"):
            assert flag in help_text, flag


class TestSyncUsersOptions:
    @pytest.fixture
    def help_text(self) -> str:
        return runner.invoke(app, ["keycloak", "sync-users", "--help"]).output

    def test_dry_run_is_offered(self, help_text: str):
        """It provisions real accounts and passwords; previewing must be possible."""
        assert "--dry-run" in help_text

    def test_group_assignment_is_offered(self, help_text: str):
        assert "--group" in help_text or "--groups" in help_text


class TestSyncOrgsOptions:
    @pytest.fixture
    def help_text(self) -> str:
        return runner.invoke(app, ["keycloak", "sync-orgs", "--help"]).output

    def test_dry_run_is_offered(self, help_text: str):
        assert "--dry-run" in help_text

    def test_it_accepts_several_owner_files(self, help_text: str):
        """Overlay files shadow the base registry — see `load_owners`."""
        assert "OWNERS_YAML" in help_text.upper()


class TestCommandsAreDistinct:
    def test_each_command_has_its_own_callback(self):
        """A copy-paste registration would silently shadow another command."""
        callbacks = [c.callback for c in keycloak_app.registered_commands]

        assert len(set(callbacks)) == len(callbacks)
