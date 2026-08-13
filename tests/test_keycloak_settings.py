"""Where the CLI gets its credentials, and which source wins.

Three layers feed `KeycloakSettings`: env vars, CLI flags, and the
`.client.secrets.yaml` written by `keycloak bootstrap`. The precedence between
them is the whole point — an operator passing `--admin-user`/`--admin-password`
to recover from a rotated client secret must not have the stale secret loaded
back over the top, and a URL or realm resolved from the wrong layer means
syncing the wrong realm.

`clean_env` (autouse, in conftest) clears `CELINE_*` first; otherwise the
developer's own shell would decide these assertions. Tests that exercise the
secrets file `chdir` into a tmp dir, since the default path is relative and the
repo root has a real one.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from celine.policies.cli.keycloak.commands._utils import build_settings
from celine.policies.cli.keycloak.settings import (
    DEFAULT_ADMIN_CLIENT_ID,
    KeycloakSettings,
    SyncUsersSettings,
    _load_secret_from_file,
)

SECRETS_YAML = """
    clients:
      celine-admin-cli:
        client_id: celine-admin-cli
        secret: from-file
      svc-other:
        client_id: svc-other
        secret: other-secret
"""


@pytest.fixture
def secrets_file(tmp_path: Path) -> Path:
    path = tmp_path / ".client.secrets.yaml"
    path.write_text(textwrap.dedent(SECRETS_YAML), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------


class TestDerivedUrls:
    """Every admin call is built from these; the master realm one is separate."""

    @pytest.fixture
    def settings(self) -> KeycloakSettings:
        return KeycloakSettings(base_url="http://kc.internal", realm="celine")

    def test_realm_url(self, settings: KeycloakSettings):
        assert settings.realm_url == "http://kc.internal/realms/celine"

    def test_admin_url(self, settings: KeycloakSettings):
        assert settings.admin_url == "http://kc.internal/admin/realms/celine"

    def test_master_realm_url_ignores_the_target_realm(self, settings: KeycloakSettings):
        """The admin-user token is issued by `master`, not by the target realm."""
        assert settings.master_realm_url == "http://kc.internal/realms/master"

    def test_a_trailing_slash_does_not_double_up(self):
        """A `//` in the path is a 404 from Keycloak, and an odd one to debug."""
        settings = KeycloakSettings(base_url="http://kc.internal/", realm="celine")
        assert settings.realm_url == "http://kc.internal/realms/celine"
        assert settings.admin_url == "http://kc.internal/admin/realms/celine"

    def test_urls_follow_the_realm(self):
        settings = KeycloakSettings(base_url="http://kc.internal", realm="staging")
        assert settings.realm_url.endswith("/realms/staging")
        assert settings.admin_url.endswith("/admin/realms/staging")


# ---------------------------------------------------------------------------
# Credential presence
# ---------------------------------------------------------------------------


class TestCredentialPresence:
    """`authenticate()` picks its flow from these two flags."""

    def test_client_credentials_need_both_halves(self):
        assert KeycloakSettings(admin_client_secret="s").has_client_credentials is True
        assert KeycloakSettings(admin_client_secret=None).has_client_credentials is False

    def test_admin_credentials_need_both_halves(self):
        assert KeycloakSettings(admin_user="a", admin_password="p").has_admin_credentials
        assert not KeycloakSettings(admin_user="a").has_admin_credentials
        assert not KeycloakSettings(admin_password="p").has_admin_credentials

    def test_the_admin_client_id_has_a_default(self):
        """`bootstrap` writes under this name, so both sides must agree on it."""
        assert KeycloakSettings().admin_client_id == DEFAULT_ADMIN_CLIENT_ID


# ---------------------------------------------------------------------------
# Env vars
# ---------------------------------------------------------------------------


class TestEnvironment:
    def test_settings_are_read_from_the_celine_keycloak_prefix(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("CELINE_KEYCLOAK_BASE_URL", "http://kc.env")
        monkeypatch.setenv("CELINE_KEYCLOAK_REALM", "env-realm")
        monkeypatch.setenv("CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET", "env-secret")

        settings = KeycloakSettings()

        assert settings.base_url == "http://kc.env"
        assert settings.realm == "env-realm"
        assert settings.admin_client_secret == "env-secret"

    def test_unprefixed_variables_are_ignored(self, monkeypatch: pytest.MonkeyPatch):
        """A bare `REALM` in the environment must not steer the CLI."""
        monkeypatch.setenv("REALM", "wrong")
        assert KeycloakSettings().realm == "celine"


# ---------------------------------------------------------------------------
# with_overrides
# ---------------------------------------------------------------------------


class TestWithOverrides:
    def test_a_given_value_replaces_the_current_one(self):
        settings = KeycloakSettings(realm="celine").with_overrides(realm="staging")
        assert settings.realm == "staging"

    def test_none_leaves_the_current_value_alone(self):
        """Unset CLI flags arrive as None; they must not blank the env values."""
        base = KeycloakSettings(base_url="http://kc.env", realm="env-realm")
        settings = base.with_overrides(base_url=None, realm=None)
        assert settings.base_url == "http://kc.env"
        assert settings.realm == "env-realm"

    def test_the_timeout_survives_an_override(self):
        base = KeycloakSettings(timeout=99.0)
        assert base.with_overrides(realm="other").timeout == 99.0

    def test_unrelated_credentials_survive_an_override(self):
        base = KeycloakSettings(admin_client_secret="keep-me", admin_user="u")
        settings = base.with_overrides(realm="other")
        assert settings.admin_client_secret == "keep-me"
        assert settings.admin_user == "u"

    def test_the_secrets_file_path_can_be_overridden(self, tmp_path: Path):
        settings = KeycloakSettings().with_overrides(secrets_file=tmp_path / "s.yaml")
        assert settings.secrets_file == tmp_path / "s.yaml"


# ---------------------------------------------------------------------------
# Reading the secrets file
# ---------------------------------------------------------------------------


class TestLoadSecretFromFile:
    def test_it_reads_the_named_clients_secret(self, secrets_file: Path):
        assert _load_secret_from_file(secrets_file, "celine-admin-cli") == "from-file"

    def test_it_reads_other_clients_too(self, secrets_file: Path):
        assert _load_secret_from_file(secrets_file, "svc-other") == "other-secret"

    def test_a_missing_file_is_not_an_error(self, tmp_path: Path):
        """Before the first `bootstrap` there is no file; the CLI must still run."""
        assert _load_secret_from_file(tmp_path / "absent.yaml") is None

    def test_an_unknown_client_yields_none(self, secrets_file: Path):
        assert _load_secret_from_file(secrets_file, "svc-nope") is None

    @pytest.mark.parametrize(
        "body",
        [
            "",  # empty file
            "just a string\n",  # not a mapping
            "clients: []\n",  # clients is not a mapping
            "clients:\n  celine-admin-cli: nope\n",  # entry is not a mapping
            "clients:\n  celine-admin-cli: {}\n",  # entry has no secret
            "clients:\n  celine-admin-cli:\n    secret: ''\n",  # empty secret
            "{{ not: valid: yaml\n",  # unparseable
        ],
    )
    def test_a_malformed_file_yields_none_rather_than_raising(
        self, tmp_path: Path, body: str
    ):
        """A half-written secrets file must degrade to "no secret", not a traceback.

        The CLI can still fall back to admin-user credentials from there.
        """
        path = tmp_path / "s.yaml"
        path.write_text(body, encoding="utf-8")
        assert _load_secret_from_file(path) is None

    def test_a_non_string_secret_is_coerced(self, tmp_path: Path):
        """An unquoted numeric secret is a YAML int; it still has to be usable."""
        path = tmp_path / "s.yaml"
        path.write_text("clients:\n  celine-admin-cli:\n    secret: 12345\n")
        assert _load_secret_from_file(path) == "12345"


class TestWithAutoSecret:
    def test_it_fills_a_missing_secret_from_the_file(self, secrets_file: Path):
        settings = KeycloakSettings(secrets_file=secrets_file).with_auto_secret()
        assert settings.admin_client_secret == "from-file"

    def test_an_existing_secret_is_never_overwritten(self, secrets_file: Path):
        """Env and CLI both outrank the file — this is how a rotation is applied."""
        settings = KeycloakSettings(
            secrets_file=secrets_file, admin_client_secret="explicit"
        ).with_auto_secret()
        assert settings.admin_client_secret == "explicit"

    def test_only_the_default_admin_client_is_auto_loaded(self, secrets_file: Path):
        """A custom admin client must state its own secret.

        Silently loading `celine-admin-cli`'s would authenticate as the wrong
        client, or fail confusingly.
        """
        settings = KeycloakSettings(
            secrets_file=secrets_file, admin_client_id="svc-other"
        ).with_auto_secret()
        assert settings.admin_client_secret is None

    def test_an_explicit_path_argument_wins(self, tmp_path: Path, secrets_file: Path):
        other = tmp_path / "other.yaml"
        other.write_text("clients:\n  celine-admin-cli:\n    secret: from-arg\n")
        settings = KeycloakSettings(secrets_file=secrets_file).with_auto_secret(other)
        assert settings.admin_client_secret == "from-arg"

    def test_a_missing_file_leaves_the_settings_untouched(self, tmp_path: Path):
        settings = KeycloakSettings(secrets_file=tmp_path / "absent.yaml").with_auto_secret()
        assert settings.admin_client_secret is None


# ---------------------------------------------------------------------------
# build_settings — the assembly every command calls
# ---------------------------------------------------------------------------


class TestBuildSettings:
    def _build(self, **kwargs):
        params: dict = {
            "base_url": None,
            "realm": None,
            "admin_user": None,
            "admin_password": None,
            "admin_client_id": None,
            "admin_client_secret": None,
        }
        params.update(kwargs)
        return build_settings(**params)

    def test_cli_flags_override_the_environment(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        # away from the repo root, whose real .client.secrets.yaml is the
        # default path and would be read by with_auto_secret()
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CELINE_KEYCLOAK_REALM", "env-realm")
        settings = self._build(realm="flag-realm")
        assert settings.realm == "flag-realm"

    def test_the_environment_is_used_when_no_flag_is_given(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CELINE_KEYCLOAK_BASE_URL", "http://kc.env")
        assert self._build().base_url == "http://kc.env"

    def test_the_secret_is_auto_loaded_when_no_admin_user_is_given(
        self, secrets_file: Path
    ):
        settings = self._build(secrets_file=secrets_file)
        assert settings.admin_client_secret == "from-file"

    def test_admin_user_credentials_suppress_the_auto_loaded_secret(
        self, secrets_file: Path
    ):
        """The documented recovery path: `--admin-user` with a stale client secret.

        If the file's secret were loaded anyway, `authenticate()` would prefer
        the client-credentials flow and fail with the very secret the operator
        is working around.
        """
        settings = self._build(
            admin_user="admin", admin_password="admin", secrets_file=secrets_file
        )
        assert settings.admin_client_secret is None
        assert settings.has_admin_credentials is True

    def test_half_given_admin_credentials_still_auto_load(self, secrets_file: Path):
        """`--admin-user` alone cannot authenticate, so the file is still the hope."""
        settings = self._build(admin_user="admin", secrets_file=secrets_file)
        assert settings.admin_client_secret == "from-file"

    def test_the_secrets_file_flag_reaches_the_settings(self, secrets_file: Path):
        """`bootstrap` writes back to `settings.secrets_file`, so it must propagate."""
        settings = self._build(secrets_file=secrets_file)
        assert settings.secrets_file == secrets_file

    def test_an_explicit_client_secret_is_kept(self, secrets_file: Path):
        settings = self._build(admin_client_secret="explicit", secrets_file=secrets_file)
        assert settings.admin_client_secret == "explicit"

    def test_a_custom_admin_client_is_not_given_the_files_secret(
        self, secrets_file: Path
    ):
        settings = self._build(admin_client_id="svc-other", secrets_file=secrets_file)
        assert settings.admin_client_secret is None

    def test_it_works_with_no_inputs_at_all(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        """Bare `celine-policies keycloak status` in an empty directory."""
        monkeypatch.chdir(tmp_path)
        settings = self._build()
        assert settings.realm == "celine"
        assert settings.admin_client_secret is None


# ---------------------------------------------------------------------------
# sync-users settings
# ---------------------------------------------------------------------------


class TestSyncUsersSettings:
    def test_defaults_are_conservative(self):
        """No dry-run surprise, and no shared password unless one is configured."""
        settings = SyncUsersSettings()
        assert settings.dry_run is False
        assert settings.temporary is True
        assert settings.temp_password is None
        assert settings.groups == []

    def test_env_vars_are_read_from_the_sync_users_prefix(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("CELINE_SYNC_USERS_REC_YAML", "/tmp/rec.yaml")
        monkeypatch.setenv("CELINE_SYNC_USERS_TEMP_PASSWORD", "demo123")
        monkeypatch.setenv("CELINE_SYNC_USERS_DRY_RUN", "true")

        settings = SyncUsersSettings()

        assert settings.rec_yaml == Path("/tmp/rec.yaml")
        assert settings.temp_password == "demo123"
        assert settings.dry_run is True

    def test_overrides_replace_values(self):
        settings = SyncUsersSettings(dry_run=False).with_overrides(dry_run=True)
        assert settings.dry_run is True

    def test_none_leaves_values_alone(self):
        base = SyncUsersSettings(temp_password="keep", dry_run=True)
        settings = base.with_overrides(temp_password=None, dry_run=None)
        assert settings.temp_password == "keep"
        assert settings.dry_run is True

    def test_false_is_an_override_not_an_absence(self):
        """`with_overrides` tests against None, so `--no-dry-run` must land.

        A truthiness check here would make disabling dry-run impossible.
        """
        base = SyncUsersSettings(dry_run=True, temporary=True)
        settings = base.with_overrides(dry_run=False, temporary=False)
        assert settings.dry_run is False
        assert settings.temporary is False

    def test_an_empty_group_list_is_an_override(self):
        base = SyncUsersSettings(groups=["/viewers"])
        assert base.with_overrides(groups=[]).groups == []

    def test_a_configured_password_is_returned_verbatim(self):
        """Demo realms hand the same password to everyone, on purpose."""
        settings = SyncUsersSettings(temp_password="demo123")
        assert settings.generate_password() == "demo123"
        assert settings.generate_password() == "demo123"

    def test_without_one_each_password_is_random(self):
        settings = SyncUsersSettings()
        passwords = {settings.generate_password() for _ in range(20)}
        assert len(passwords) == 20

    def test_generated_passwords_avoid_ambiguous_characters(self):
        """These get read aloud and retyped at onboarding: no `l`, `O`, `0`, `1`."""
        settings = SyncUsersSettings()
        for _ in range(20):
            password = settings.generate_password()
            assert len(password) == 16
            assert not set(password) & set("loO01I")
