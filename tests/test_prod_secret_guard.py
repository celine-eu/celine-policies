"""The production guard: `keycloak sync` refuses to install placeholder secrets.

`clients.yaml` writes every secret as `${SVC_X_SECRET:-svc-x}`. Locally the
fallback is the point — one `task keycloak:sync` and the realm works. In a
production realm the same fallback silently installs a client credential that
anyone can derive from the client list, and nothing downstream ever objects:
the sync succeeds, the services authenticate, and the secret is public.

So the default is strict. `ENV` must *say* it is a development environment for
the placeholders to be accepted; unset, misspelled, or absent means production.
That direction matters — being strict in dev costs one export, the other way
round costs a credential rotation across nineteen clients.

The check runs before authentication, so a misconfigured deployment fails on its
own machine instead of halfway through rewriting a live realm.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from celine.policies.cli.keycloak.models import ClientConfig, KeycloakConfig
from celine.policies.cli.keycloak.settings import KeycloakSettings
from celine.policies.cli.keycloak.sync import SyncResult
from celine.policies.cli.main import app

runner = CliRunner()

CLIENTS_YAML = Path(__file__).resolve().parents[1] / "clients.yaml"


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "clients.yaml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Which environment are we in
# ---------------------------------------------------------------------------


class TestEnvironmentResolution:
    def test_the_default_is_production(self):
        """Nothing set anywhere: the strict path, not the convenient one."""
        settings = KeycloakSettings()

        assert settings.env == "prod"
        assert settings.is_production is True

    @pytest.mark.parametrize("value", ["dev", "development", "local", "test", "ci"])
    def test_known_development_names_opt_out(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ):
        monkeypatch.setenv("ENV", value)

        assert KeycloakSettings().is_production is False

    @pytest.mark.parametrize("value", ["DEV", "Dev", " dev ", "dev\n"])
    def test_the_comparison_is_forgiving_about_shape(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ):
        """Case and stray whitespace come free with `export ENV=$SOMETHING`."""
        monkeypatch.setenv("ENV", value)

        assert KeycloakSettings().is_production is False

    @pytest.mark.parametrize("value", ["prod", "production", "staging", "", "devv", "0"])
    def test_everything_else_is_production(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ):
        """Including a typo, and including staging.

        A misspelled `devv` failing loudly is recoverable; a misspelled value
        quietly disabling the check is how the placeholder reaches the realm.
        """
        monkeypatch.setenv("ENV", value)

        assert KeycloakSettings().is_production is True

    def test_the_prefixed_name_wins_over_the_bare_one(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """`ENV` is also a POSIX shell variable, so it is the weakest source."""
        monkeypatch.setenv("ENV", "prod")
        monkeypatch.setenv("CELINE_ENV", "dev")

        assert KeycloakSettings().is_production is False

    def test_the_keycloak_prefixed_name_wins_over_both(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("ENV", "dev")
        monkeypatch.setenv("CELINE_ENV", "dev")
        monkeypatch.setenv("CELINE_KEYCLOAK_ENV", "prod")

        assert KeycloakSettings().is_production is True

    def test_it_can_be_set_explicitly(self):
        assert KeycloakSettings(env="dev").is_production is False

    def test_it_survives_cli_overrides(self, monkeypatch: pytest.MonkeyPatch):
        """`build_settings` rebuilds the object per flag; the mode must persist."""
        monkeypatch.setenv("ENV", "dev")

        settings = KeycloakSettings().with_overrides(realm="other")

        assert settings.is_production is False


# ---------------------------------------------------------------------------
# What counts as a placeholder
# ---------------------------------------------------------------------------


class TestPlaceholderDetection:
    def test_a_secret_equal_to_the_client_id_is_a_placeholder(self):
        """The `${SVC_X_SECRET:-svc-x}` fallback, resolved with nothing set."""
        assert ClientConfig(client_id="svc-x", secret="svc-x").has_placeholder_secret()

    def test_an_empty_secret_is_a_placeholder(self):
        """`${SVC_X_SECRET}` with no default resolves to "".

        `create_client` sends no secret at all for a falsy value, so whatever
        Keycloak already had stays in force — a sync that reports success and
        changes nothing.
        """
        assert ClientConfig(client_id="svc-x", secret="").has_placeholder_secret()

    def test_a_whitespace_secret_is_a_placeholder(self):
        assert ClientConfig(client_id="svc-x", secret="   ").has_placeholder_secret()

    def test_a_real_secret_is_not(self):
        client = ClientConfig(client_id="svc-x", secret="8f3c1e77-real")
        assert client.has_placeholder_secret() is False

    def test_an_absent_secret_is_not_a_placeholder(self):
        """No `secret:` key means Keycloak generates one — the good path.

        Flagging it would push people towards writing secrets into the YAML.
        """
        assert ClientConfig(client_id="svc-x").has_placeholder_secret() is False

    def test_a_secret_merely_containing_the_client_id_is_not_flagged(self):
        """Only exact equality. `svc-x-8f3c1e` is a fine secret."""
        client = ClientConfig(client_id="svc-x", secret="svc-x-8f3c1e77")
        assert client.has_placeholder_secret() is False

    def test_offenders_are_listed_sorted(self):
        config = KeycloakConfig(
            clients=[
                ClientConfig(client_id="svc-z", secret="svc-z"),
                ClientConfig(client_id="svc-a", secret="svc-a"),
                ClientConfig(client_id="svc-ok", secret="real-secret"),
                ClientConfig(client_id="svc-none"),
            ]
        )
        assert config.clients_with_placeholder_secrets() == ["svc-a", "svc-z"]

    def test_a_clean_config_reports_nothing(self):
        config = KeycloakConfig(
            clients=[ClientConfig(client_id="svc-a", secret="real-secret")]
        )
        assert config.clients_with_placeholder_secrets() == []


class TestSecretSource:
    """The error message names the variable to set, not just the client.

    Derived from the raw YAML rather than from the client_id, because the two
    do not match: `svc-dataset-api` reads `SVC_DATASET_SECRET`.
    """

    def test_the_variable_behind_a_defaulted_placeholder_is_recovered(
        self, tmp_path: Path
    ):
        path = _write(
            tmp_path,
            """
            clients:
              - client_id: svc-dataset-api
                secret: ${SVC_DATASET_SECRET:-svc-dataset-api}
            """,
        )
        config = KeycloakConfig.from_yaml(path)

        assert config.secret_source("svc-dataset-api") == "SVC_DATASET_SECRET"

    def test_a_placeholder_without_a_default_is_recovered_too(self, tmp_path: Path):
        path = _write(
            tmp_path,
            """
            clients:
              - client_id: svc-x
                secret: ${SVC_X_SECRET}
            """,
        )
        assert KeycloakConfig.from_yaml(path).secret_source("svc-x") == "SVC_X_SECRET"

    def test_a_hardcoded_secret_has_no_source(self, tmp_path: Path):
        path = _write(
            tmp_path,
            """
            clients:
              - client_id: svc-x
                secret: literal-secret
            """,
        )
        assert KeycloakConfig.from_yaml(path).secret_source("svc-x") is None

    def test_an_unknown_client_has_no_source(self, tmp_path: Path):
        path = _write(tmp_path, "clients: []\n")
        assert KeycloakConfig.from_yaml(path).secret_source("svc-ghost") is None

    def test_a_config_built_in_memory_has_no_sources(self):
        """Nothing crashes when the config never came from a file."""
        config = KeycloakConfig(clients=[ClientConfig(client_id="svc-x", secret="svc-x")])

        assert config.secret_source("svc-x") is None
        assert config.clients_with_placeholder_secrets() == ["svc-x"]


# ---------------------------------------------------------------------------
# The shipped config
# ---------------------------------------------------------------------------


class TestShippedClientsYaml:
    def test_every_client_falls_back_to_a_placeholder(self):
        """With no secrets exported, all of them resolve to their own client_id.

        This is the state a fresh checkout is in, and precisely what must not
        reach a production realm — the guard's whole reason for existing.
        """
        config = KeycloakConfig.from_yaml(CLIENTS_YAML)

        assert len(config.clients_with_placeholder_secrets()) == len(config.clients)

    def test_exporting_a_secret_clears_that_client(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """And the variable the guard names is the one that actually works."""
        config = KeycloakConfig.from_yaml(CLIENTS_YAML)
        source = config.secret_source("svc-dataset-api")
        assert source, "svc-dataset-api no longer reads its secret from the environment"

        monkeypatch.setenv(source, "a-real-secret")
        reloaded = KeycloakConfig.from_yaml(CLIENTS_YAML)

        assert "svc-dataset-api" not in reloaded.clients_with_placeholder_secrets()

    def test_every_client_names_the_variable_that_fixes_it(self):
        """An offender the message cannot explain is an unactionable failure."""
        config = KeycloakConfig.from_yaml(CLIENTS_YAML)

        unexplained = [
            client_id
            for client_id in config.clients_with_placeholder_secrets()
            if not config.secret_source(client_id)
        ]
        assert unexplained == []


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------


@pytest.fixture
def async_sync():
    """Stub the part that talks to Keycloak.

    Lets the tests assert not just the exit code but *whether the sync got that
    far* — the guard is only worth anything if it fires before authentication.
    """
    with patch(
        "celine.policies.cli.keycloak.commands.sync._async_sync",
        new=AsyncMock(return_value=SyncResult()),
    ) as stub:
        yield stub


@pytest.fixture
def dev_config(tmp_path: Path) -> Path:
    """Two clients, both on the placeholder fallback."""
    return _write(
        tmp_path,
        """
        realm: celine
        scopes:
          - name: dataset.query
        clients:
          - client_id: svc-dataset-api
            secret: ${SVC_DATASET_SECRET:-svc-dataset-api}
            scopes_prefix: dataset
            default_scopes: [dataset.query]
          - client_id: svc-forecast
            secret: ${SVC_FORECAST_SECRET:-svc-forecast}
            scopes_prefix: forecast
        """,
    )


def _sync(config_path: Path):
    return runner.invoke(app, ["keycloak", "sync", str(config_path), "--dry-run"])


class TestSyncCommandGuard:
    def test_it_refuses_by_default(self, dev_config: Path, async_sync: AsyncMock):
        """No ENV set at all — the case this whole change is about."""
        result = _sync(dev_config)

        assert result.exit_code == 1

    def test_it_fails_before_contacting_keycloak(
        self, dev_config: Path, async_sync: AsyncMock
    ):
        """Nothing is authenticated, fetched or written — it stops at the config."""
        _sync(dev_config)

        async_sync.assert_not_awaited()

    def test_it_names_every_offending_client(
        self, dev_config: Path, async_sync: AsyncMock
    ):
        result = _sync(dev_config)

        assert "svc-dataset-api" in result.output
        assert "svc-forecast" in result.output

    def test_it_names_the_variables_that_fix_it(
        self, dev_config: Path, async_sync: AsyncMock
    ):
        result = _sync(dev_config)

        assert "SVC_DATASET_SECRET" in result.output
        assert "SVC_FORECAST_SECRET" in result.output

    def test_it_says_how_to_opt_out(self, dev_config: Path, async_sync: AsyncMock):
        """Otherwise the first thing anyone does is start deleting the check."""
        result = _sync(dev_config)

        assert "ENV=dev" in result.output

    def test_dev_lets_the_placeholders_through(
        self, dev_config: Path, async_sync: AsyncMock, monkeypatch: pytest.MonkeyPatch
    ):
        """The local workflow stays exactly as it was."""
        monkeypatch.setenv("ENV", "dev")

        result = _sync(dev_config)

        assert result.exit_code == 0
        async_sync.assert_awaited_once()

    def test_real_secrets_pass_in_production(
        self, dev_config: Path, async_sync: AsyncMock, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("SVC_DATASET_SECRET", "8f3c1e77-real")
        monkeypatch.setenv("SVC_FORECAST_SECRET", "b2d9a410-real")

        result = _sync(dev_config)

        assert result.exit_code == 0
        async_sync.assert_awaited_once()

    def test_one_missing_secret_is_enough_to_stop_the_sync(
        self, dev_config: Path, async_sync: AsyncMock, monkeypatch: pytest.MonkeyPatch
    ):
        """Partial credentials are still a public credential on one client."""
        monkeypatch.setenv("SVC_DATASET_SECRET", "8f3c1e77-real")

        result = _sync(dev_config)

        assert result.exit_code == 1
        assert "svc-forecast" in result.output
        assert "svc-dataset-api" not in result.output.split("Refusing to sync")[1]

    def test_a_config_declaring_no_secrets_passes_in_production(
        self, tmp_path: Path, async_sync: AsyncMock
    ):
        """Letting Keycloak generate them is the recommended production shape."""
        config = _write(
            tmp_path,
            """
            clients:
              - client_id: svc-x
                scopes_prefix: x
            """,
        )

        assert _sync(config).exit_code == 0

    def test_the_active_environment_is_reported(
        self, dev_config: Path, async_sync: AsyncMock, monkeypatch: pytest.MonkeyPatch
    ):
        """So a surprising refusal is self-explanatory in CI logs."""
        monkeypatch.setenv("ENV", "dev")

        result = _sync(dev_config)

        assert "Environment: dev" in result.output

    def test_the_guard_applies_to_a_dry_run_too(
        self, dev_config: Path, async_sync: AsyncMock
    ):
        """`--dry-run` is where the misconfiguration should surface first."""
        result = runner.invoke(
            app, ["keycloak", "sync", str(dev_config), "--dry-run"]
        )

        assert result.exit_code == 1

    def test_the_guard_applies_to_a_real_run(
        self, dev_config: Path, async_sync: AsyncMock
    ):
        result = runner.invoke(app, ["keycloak", "sync", str(dev_config)])

        assert result.exit_code == 1
        async_sync.assert_not_awaited()
