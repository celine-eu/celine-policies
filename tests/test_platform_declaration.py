"""`platform.yaml`, its overlays, and how `bootstrap` converges a realm on them.

The platform level is written by `bootstrap` alone (plan each-cli-command-owns-one-level).
What is guarded here is the ownership rule that makes that safe on a realm already in
service: **only declared keys are written**, a key left out is left alone, a credential or
a per-environment switch cannot be declared, and a deployment overlay can narrow the
languages and change nothing else. Every refusal happens before the first write.

Keycloak is faked. That it accepts a partial realm `PUT`, masks the SMTP password and
takes any theme name without complaint was measured on a throwaway 26.7.3 (the plan's
work directory, Phase 1). These tests hold the decisions built on those measurements.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from celine.policies.cli.keycloak.platform import (
    OVERLAY_REALM_SETTINGS,
    REFUSED_REALM_SETTINGS,
    THEME_LOCALES,
    PlatformDeclarationError,
    PlatformNotReady,
    check_themes,
    converge_platform,
    env_override_name,
    load_platform,
    plan_realm_settings,
    require_platform,
)
from celine.policies.cli.keycloak.settings import KeycloakSettings, SmtpSettings

REPO_ROOT = Path(__file__).resolve().parents[1]
PLATFORM_YAML = REPO_ROOT / "platform.yaml"
IMPORT_JSON = REPO_ROOT / "config" / "keycloak" / "import" / "realm-celine.json"


def write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text)
    return path


# ---------------------------------------------------------------------------
# The shipped declaration
# ---------------------------------------------------------------------------


class TestTheShippedDeclaration:
    def test_it_loads(self):
        declaration = load_platform(PLATFORM_YAML)
        assert declaration.realm_settings
        assert declaration.role_groups

    def test_it_carries_the_invitation_settings(self):
        """The keys `a-participant-is-invited-and-sets-their-own-password` fixes."""
        settings = load_platform(PLATFORM_YAML).realm_settings
        assert settings["resetPasswordAllowed"] is True
        assert settings["internationalizationEnabled"] is True
        assert settings["supportedLocales"] == ["it", "en", "es"]
        assert settings["defaultLocale"] == "it"
        assert settings["emailTheme"] == "rec"
        assert settings["actionTokenGeneratedByAdminLifespan"] == 604800
        assert settings["actionTokenGeneratedByUserLifespan"] == 3600

    def test_it_carries_the_features_other_commands_check(self):
        settings = load_platform(PLATFORM_YAML).realm_settings
        assert settings["organizationsEnabled"] is True
        assert settings["adminPermissionsEnabled"] is True

    def test_the_lifespans_are_the_deployed_ones(self):
        """Requester, 2026-09-14: infra's values, not Keycloak's defaults."""
        settings = load_platform(PLATFORM_YAML).realm_settings
        assert settings["accessTokenLifespan"] == 3600
        assert settings["accessTokenLifespanForImplicitFlow"] == 3600
        assert settings["ssoSessionIdleTimeout"] == 86400
        assert settings["ssoSessionMaxLifespan"] == 86400

    def test_the_role_groups_carry_the_roles_the_imports_map(self):
        import json

        imported = {
            g["path"]: g["realmRoles"] for g in json.loads(IMPORT_JSON.read_text())["groups"]
        }
        declared = {g.path: [g.realm_role] for g in load_platform(PLATFORM_YAML).role_groups}
        assert declared == imported

    def test_the_import_file_does_not_carry_the_bootstrap_keys(self):
        """P3: an import reaches new realms only; these keys belong to bootstrap."""
        import json

        imported = json.loads(IMPORT_JSON.read_text())
        for key in (
            "resetPasswordAllowed",
            "internationalizationEnabled",
            "supportedLocales",
            "defaultLocale",
            "actionTokenGeneratedByAdminLifespan",
            "actionTokenGeneratedByUserLifespan",
        ):
            assert key not in imported


# ---------------------------------------------------------------------------
# What a declaration may say
# ---------------------------------------------------------------------------


class TestEveryAcceptedKeyIsAKeycloakKey:
    """A key Keycloak does not have is a `400` on the whole realm `PUT`.

    Caught on a real 26.7.3: `maxLoginFailures`, copied from infra's realm template, is
    not a field of any realm representation (`failureFactor` is "max login failures"),
    and `bootstrap` failed on its first real run. The fixture is the key set a 26.7.3
    realm reads back.
    """

    KEYS = {
        line.strip()
        for line in (REPO_ROOT / "tests" / "fixtures" / "keycloak-26.7.3-realm-keys.txt").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }

    def test_every_accepted_key_exists_on_the_server(self):
        from celine.policies.cli.keycloak.platform import REALM_SETTING_TYPES

        assert set(REALM_SETTING_TYPES) - self.KEYS == set()

    def test_the_keys_bootstrap_writes_from_the_environment_exist(self):
        assert {"bruteForceProtected", "smtpServer"} <= self.KEYS


class TestWhatADeclarationMaySay:
    @pytest.mark.parametrize("key", sorted(REFUSED_REALM_SETTINGS))
    def test_a_refused_key_is_refused_with_its_reason(self, tmp_path, key):
        path = write(tmp_path, "platform.yaml", f"realm_settings:\n  {key}: true\n")
        with pytest.raises(PlatformDeclarationError) as exc:
            load_platform(path)
        assert key in str(exc.value)
        assert REFUSED_REALM_SETTINGS[key] in str(exc.value)

    def test_an_unknown_realm_key_is_refused(self, tmp_path):
        path = write(tmp_path, "platform.yaml", "realm_settings:\n  sslRequired: none\n")
        with pytest.raises(PlatformDeclarationError, match="sslRequired"):
            load_platform(path)

    def test_an_unknown_top_level_key_is_refused(self, tmp_path):
        path = write(tmp_path, "platform.yaml", "realm: celine\n")
        with pytest.raises(PlatformDeclarationError, match="realm"):
            load_platform(path)

    @pytest.mark.parametrize(
        "line",
        [
            'resetPasswordAllowed: "true"',
            "accessTokenLifespan: true",
            "accessTokenLifespan: -1",
            'defaultLocale: ""',
            "supportedLocales: it",
            "supportedLocales: [it, it]",
        ],
    )
    def test_a_value_of_the_wrong_type_is_refused(self, tmp_path, line):
        path = write(tmp_path, "platform.yaml", f"realm_settings:\n  {line}\n")
        with pytest.raises(PlatformDeclarationError, match="must be"):
            load_platform(path)

    @pytest.mark.parametrize("group", ["admins", "/a/b", "/"])
    def test_a_role_group_path_must_be_top_level(self, tmp_path, group):
        path = write(
            tmp_path, "platform.yaml", f"role_groups:\n  - path: {group!r}\n    realm_role: admin\n"
        )
        with pytest.raises(PlatformDeclarationError, match="top-level"):
            load_platform(path)

    def test_a_default_locale_outside_the_supported_ones_is_refused(self, tmp_path):
        path = write(
            tmp_path,
            "platform.yaml",
            "realm_settings:\n  supportedLocales: [en, es]\n  defaultLocale: it\n",
        )
        with pytest.raises(PlatformDeclarationError, match="defaultLocale"):
            load_platform(path)

    def test_a_missing_file_is_refused(self, tmp_path):
        with pytest.raises(PlatformDeclarationError, match="not found"):
            load_platform(tmp_path / "platform.yaml")


# ---------------------------------------------------------------------------
# Overlays (Phase 2b): supported languages only
# ---------------------------------------------------------------------------


class TestAnOverlayNarrowsTheLanguagesAndNothingElse:
    def test_the_only_overridable_key(self):
        assert OVERLAY_REALM_SETTINGS == {"supportedLocales"}

    def test_it_changes_only_the_key_it_names_and_reports_the_source(self, tmp_path):
        base = load_platform(PLATFORM_YAML)
        overlay = write(tmp_path, "staging.yaml", "realm_settings:\n  supportedLocales: [it, en]\n")

        merged = load_platform(PLATFORM_YAML, [overlay])

        assert merged.realm_settings["supportedLocales"] == ["it", "en"]
        assert merged.sources["supportedLocales"] == str(overlay)
        others = {k: v for k, v in merged.realm_settings.items() if k != "supportedLocales"}
        assert others == {k: v for k, v in base.realm_settings.items() if k != "supportedLocales"}
        assert all(
            src == str(PLATFORM_YAML) for k, src in merged.sources.items() if k != "supportedLocales"
        )
        assert merged.role_groups == base.role_groups

    def test_the_last_overlay_wins(self, tmp_path):
        first = write(tmp_path, "a.yaml", "realm_settings:\n  supportedLocales: [it, en]\n")
        second = write(tmp_path, "b.yaml", "realm_settings:\n  supportedLocales: [it, es]\n")

        merged = load_platform(PLATFORM_YAML, [first, second])

        assert merged.realm_settings["supportedLocales"] == ["it", "es"]
        assert merged.sources["supportedLocales"] == str(second)

    @pytest.mark.parametrize(
        "line",
        [
            "defaultLocale: en",
            "registrationAllowed: true",
            "emailTheme: keycloak",
            "actionTokenGeneratedByAdminLifespan: 60",
        ],
    )
    def test_any_other_accepted_key_is_refused(self, tmp_path, line):
        overlay = write(tmp_path, "o.yaml", f"realm_settings:\n  {line}\n")
        with pytest.raises(PlatformDeclarationError, match="only"):
            load_platform(PLATFORM_YAML, [overlay])

    @pytest.mark.parametrize("key", sorted(REFUSED_REALM_SETTINGS))
    def test_a_refused_key_is_refused_in_an_overlay_too(self, tmp_path, key):
        overlay = write(tmp_path, "o.yaml", f"realm_settings:\n  {key}: x\n")
        with pytest.raises(PlatformDeclarationError, match=key):
            load_platform(PLATFORM_YAML, [overlay])

    def test_an_unknown_key_is_refused(self, tmp_path):
        overlay = write(tmp_path, "o.yaml", "realm_settings:\n  sslRequired: none\n")
        with pytest.raises(PlatformDeclarationError, match="sslRequired"):
            load_platform(PLATFORM_YAML, [overlay])

    def test_role_groups_are_refused(self, tmp_path):
        overlay = write(tmp_path, "o.yaml", "role_groups: []\n")
        with pytest.raises(PlatformDeclarationError, match="role_groups"):
            load_platform(PLATFORM_YAML, [overlay])

    def test_dropping_the_default_locale_is_refused_naming_both_files(self, tmp_path):
        overlay = write(tmp_path, "o.yaml", "realm_settings:\n  supportedLocales: [en, es]\n")
        with pytest.raises(PlatformDeclarationError) as exc:
            load_platform(PLATFORM_YAML, [overlay])
        assert str(overlay) in str(exc.value)
        assert str(PLATFORM_YAML) in str(exc.value)

    def test_a_locale_the_themes_do_not_ship_is_refused(self, tmp_path):
        overlay = write(tmp_path, "o.yaml", "realm_settings:\n  supportedLocales: [it, de]\n")
        with pytest.raises(PlatformDeclarationError, match="de"):
            load_platform(PLATFORM_YAML, [overlay])

    def test_the_theme_locales_are_the_bundles_the_rec_themes_ship(self):
        for kind in ("login", "email"):
            bundles = REPO_ROOT / "keycloak" / "themes" / "rec" / kind / "messages"
            shipped = {p.stem.removeprefix("messages_") for p in bundles.glob("messages_*.properties")}
            assert shipped == THEME_LOCALES


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------


class TestPlanningTheSettings:
    def test_only_keys_that_differ_are_planned(self):
        changes = plan_realm_settings(
            {"resetPasswordAllowed": True, "loginTheme": "rec"},
            {"resetPasswordAllowed": False, "loginTheme": "rec", "verifyEmail": True},
            {"resetPasswordAllowed": "platform.yaml", "loginTheme": "platform.yaml"},
        )
        assert [(c.key, c.current, c.desired, c.source) for c in changes] == [
            ("resetPasswordAllowed", False, True, "platform.yaml")
        ]

    def test_the_order_of_supported_locales_is_not_a_change(self):
        """Keycloak keeps them as a set; a reordered read-back must not plan a write."""
        assert plan_realm_settings(
            {"supportedLocales": ["it", "en", "es"]}, {"supportedLocales": ["es", "it", "en"]}, {}
        ) == []

    def test_a_missing_key_is_a_change(self):
        assert len(plan_realm_settings({"emailTheme": "rec"}, {}, {})) == 1


class TestTheThemeCheck:
    INFO = {"themes": {"login": [{"name": "keycloak"}, {"name": "rec"}], "email": [{"name": "keycloak"}]}}

    def test_a_listed_theme_passes(self):
        check_themes({"loginTheme": "rec"}, self.INFO)

    def test_an_unlisted_theme_is_refused_naming_what_is_listed(self):
        with pytest.raises(PlatformDeclarationError) as exc:
            check_themes({"emailTheme": "rec"}, self.INFO)
        assert "emailTheme" in str(exc.value)
        assert "keycloak" in str(exc.value)


# ---------------------------------------------------------------------------
# Converging a realm
# ---------------------------------------------------------------------------


class FakeRealm:
    """The Admin API calls `converge_platform` makes, against an in-memory realm."""

    def __init__(
        self,
        realm: dict[str, Any] | None = None,
        *,
        roles: set[str] | None = None,
        groups: dict[str, set[str]] | None = None,
        themes: dict[str, list[str]] | None = None,
        sticky: bool = True,
    ):
        self.realm = dict(realm or {})
        self.roles = set(roles or ())
        # path -> realm roles mapped onto it
        self.groups = {path: set(r) for path, r in (groups or {}).items()}
        self.themes = themes or {"login": ["keycloak", "rec"], "email": ["keycloak", "rec"]}
        self.sticky = sticky
        self.puts: list[dict[str, Any]] = []
        self.writes: list[tuple] = []

    async def get_server_info(self):
        return {"themes": {k: [{"name": n} for n in v] for k, v in self.themes.items()}}

    async def get_realm_settings(self):
        realm = dict(self.realm)
        if "password" in realm.get("smtpServer", {}):
            # Measured on 26.7.3: the password is never returned.
            realm["smtpServer"] = dict(realm["smtpServer"], password="**********")
        return realm

    async def update_realm_settings(self, settings):
        self.puts.append(dict(settings))
        self.writes.append(("realm", tuple(sorted(settings))))
        if self.sticky:
            self.realm.update(settings)

    async def get_admin_permissions_client_uuid(self):
        return "uuid-ap" if self.realm.get("adminPermissionsEnabled") else None

    async def get_realm_role(self, name):
        return {"id": f"role-{name}", "name": name} if name in self.roles else None

    async def create_realm_role(self, name):
        self.writes.append(("role", name))
        self.roles.add(name)

    async def get_group_by_path(self, path):
        return {"id": f"id{path}", "path": path} if path in self.groups else None

    async def create_group(self, name):
        self.writes.append(("group", f"/{name}"))
        self.groups[f"/{name}"] = set()
        return f"id/{name}"

    async def get_group_realm_role_names(self, group_id):
        return set(self.groups[group_id.removeprefix("id")])

    async def add_group_realm_role(self, group_id, role):
        self.writes.append(("mapping", group_id.removeprefix("id"), role))
        self.groups[group_id.removeprefix("id")].add(role)


def a_declaration(tmp_path: Path, settings: str = "", groups: str = ""):
    text = ""
    if settings:
        text += "realm_settings:\n" + "".join(f"  {line}\n" for line in settings.splitlines())
    if groups:
        text += "role_groups:\n" + groups
    return load_platform(write(tmp_path, "platform.yaml", text))


async def converge(kc, declaration, *, dry_run=False, brute_force_protected=False, smtp=None):
    return await converge_platform(
        kc, declaration, brute_force_protected=brute_force_protected, dry_run=dry_run, smtp=smtp
    )


class TestBootstrapWritesOnlyDeclaredKeys:
    @pytest.mark.asyncio
    async def test_the_put_carries_only_the_keys_that_differ(self, tmp_path):
        declaration = a_declaration(tmp_path, "resetPasswordAllowed: true\nloginTheme: rec")
        kc = FakeRealm(
            {"resetPasswordAllowed": False, "loginTheme": "rec", "bruteForceProtected": False,
             "verifyEmail": True, "smtpServer": {"password": "**********"}}
        )

        await converge(kc, declaration)

        assert kc.puts == [{"resetPasswordAllowed": True}]

    @pytest.mark.asyncio
    async def test_an_undeclared_key_is_left_alone(self, tmp_path):
        declaration = a_declaration(tmp_path, "resetPasswordAllowed: true")
        kc = FakeRealm({"verifyEmail": True, "registrationAllowed": True})

        await converge(kc, declaration)

        assert kc.realm["verifyEmail"] is True
        assert kc.realm["registrationAllowed"] is True
        assert all("verifyEmail" not in put and "registrationAllowed" not in put for put in kc.puts)

    @pytest.mark.asyncio
    async def test_a_second_run_changes_nothing(self, tmp_path):
        declaration = load_platform(PLATFORM_YAML)
        kc = FakeRealm()

        first = await converge(kc, declaration, brute_force_protected=True)
        writes = len(kc.writes)
        second = await converge(kc, declaration, brute_force_protected=True)

        assert first.changed
        assert not second.changed
        assert len(kc.writes) == writes

    @pytest.mark.asyncio
    async def test_a_dry_run_reports_and_writes_nothing(self, tmp_path):
        declaration = load_platform(PLATFORM_YAML)
        kc = FakeRealm()

        result = await converge(kc, declaration, dry_run=True)

        assert result.settings and result.roles_created and result.groups_created
        assert kc.writes == []

    @pytest.mark.asyncio
    async def test_brute_force_comes_from_the_run_not_the_file(self, tmp_path):
        declaration = a_declaration(tmp_path, "failureFactor: 5")
        kc = FakeRealm({"failureFactor": 5, "bruteForceProtected": False})

        result = await converge(kc, declaration, brute_force_protected=True)

        assert [(c.key, c.source) for c in result.settings] == [
            ("bruteForceProtected", "CELINE_KEYCLOAK_BRUTE_FORCE_ENABLED")
        ]

    @pytest.mark.asyncio
    async def test_a_setting_that_does_not_stick_fails_the_run(self, tmp_path):
        declaration = a_declaration(tmp_path, "resetPasswordAllowed: true")
        kc = FakeRealm({"bruteForceProtected": False}, sticky=False)

        with pytest.raises(PlatformDeclarationError, match="did not take"):
            await converge(kc, declaration)

    @pytest.mark.asyncio
    async def test_an_unlisted_theme_is_refused_before_any_write(self, tmp_path):
        declaration = load_platform(PLATFORM_YAML)
        kc = FakeRealm(themes={"login": ["keycloak", "rec"], "email": ["keycloak"]})

        with pytest.raises(PlatformDeclarationError, match="emailTheme"):
            await converge(kc, declaration)

        assert kc.writes == []


class TestTheRoleGroups:
    GROUPS = "  - path: /admins\n    realm_role: admin\n  - path: /viewers\n    realm_role: viewer\n"

    @pytest.mark.asyncio
    async def test_absent_groups_are_created_with_their_role(self, tmp_path):
        kc = FakeRealm({"bruteForceProtected": False})

        await converge(kc, a_declaration(tmp_path, groups=self.GROUPS))

        assert kc.roles == {"admin", "viewer"}
        assert kc.groups == {"/admins": {"admin"}, "/viewers": {"viewer"}}

    @pytest.mark.asyncio
    async def test_an_existing_group_gains_the_missing_role_and_keeps_its_others(self, tmp_path):
        """What a realm whose groups `sync-users` created looks like: no role on them."""
        kc = FakeRealm(
            {"bruteForceProtected": False},
            roles={"admin", "viewer", "extra"},
            groups={"/admins": {"extra"}, "/viewers": {"viewer"}},
        )

        result = await converge(kc, a_declaration(tmp_path, groups=self.GROUPS))

        assert result.groups_created == [] and result.roles_created == []
        assert result.role_mappings_added == [("/admins", "admin")]
        assert kc.groups["/admins"] == {"extra", "admin"}


class TestTheCheckOtherCommandsMake:
    @pytest.mark.asyncio
    async def test_a_realm_without_organizations_is_refused_naming_bootstrap(self):
        with pytest.raises(PlatformNotReady, match="keycloak bootstrap") as exc:
            await require_platform(FakeRealm({"organizationsEnabled": False}), organizations=True)
        assert "organizationsEnabled" in str(exc.value)

    @pytest.mark.asyncio
    async def test_a_realm_without_admin_permissions_is_refused(self):
        with pytest.raises(PlatformNotReady, match="adminPermissionsEnabled"):
            await require_platform(FakeRealm({}), admin_permissions=True)

    @pytest.mark.asyncio
    async def test_a_ready_realm_passes_and_is_not_written(self):
        kc = FakeRealm({"organizationsEnabled": True, "adminPermissionsEnabled": True})
        await require_platform(kc, organizations=True, admin_permissions=True)
        assert kc.writes == []


class TestBruteForceActivation:
    """Requester, 2026-09-14: on by default, off in dev, the variable overrides."""

    def test_on_when_the_environment_says_nothing(self):
        assert KeycloakSettings().brute_force_protected is True

    def test_off_in_dev(self, monkeypatch):
        monkeypatch.setenv("ENV", "dev")
        assert KeycloakSettings().brute_force_protected is False

    @pytest.mark.parametrize(("env", "value", "expected"), [("dev", "true", True), ("prod", "false", False)])
    def test_the_variable_overrides_either_way(self, monkeypatch, env, value, expected):
        monkeypatch.setenv("ENV", env)
        monkeypatch.setenv("CELINE_KEYCLOAK_BRUTE_FORCE_ENABLED", value)
        assert KeycloakSettings().brute_force_protected is expected

    def test_it_survives_cli_overrides(self, monkeypatch):
        monkeypatch.setenv("CELINE_KEYCLOAK_BRUTE_FORCE_ENABLED", "false")
        assert KeycloakSettings().with_overrides(realm="other").brute_force_protected is False


# ---------------------------------------------------------------------------
# SMTP (Phase 2b)
# ---------------------------------------------------------------------------

PASSWORD = "the-smtp-password-from-the-secret"


@pytest.fixture
def smtp_env(monkeypatch):
    def set_env(**values: str) -> SmtpSettings:
        base = {
            "HOST": "smtp.example.test",
            "PORT": "587",
            "FROM": "noreply@example.test",
            "FROM_DISPLAY_NAME": "CELINE",
            "STARTTLS": "true",
            "USER": "mailer",
            "PASSWORD": PASSWORD,
        }
        base.update(values)
        for key, value in base.items():
            monkeypatch.setenv(f"CELINE_KEYCLOAK_SMTP_{key}", value)
        return SmtpSettings()

    return set_env


def smtp_puts(kc: FakeRealm) -> list[dict]:
    return [put["smtpServer"] for put in kc.puts if "smtpServer" in put]


class TestSmtpComesFromTheEnvironment:
    @pytest.mark.asyncio
    async def test_unset_it_is_left_alone(self, tmp_path):
        kc = FakeRealm({"bruteForceProtected": False, "smtpServer": {"host": "mailpit", "from": "x"}})

        result = await converge(kc, a_declaration(tmp_path), smtp=SmtpSettings())

        assert smtp_puts(kc) == []
        assert result.smtp == [] and not result.smtp_password_applied

    @pytest.mark.asyncio
    async def test_set_it_is_written_whole_with_the_password(self, tmp_path, smtp_env):
        kc = FakeRealm({"bruteForceProtected": False})

        result = await converge(kc, a_declaration(tmp_path), smtp=smtp_env())

        assert smtp_puts(kc) == [
            {
                "host": "smtp.example.test",
                "port": "587",
                "from": "noreply@example.test",
                "fromDisplayName": "CELINE",
                "ssl": "false",
                "starttls": "true",
                "auth": "true",
                "user": "mailer",
                "password": PASSWORD,
            }
        ]
        assert {c.key for c in result.smtp} >= {"smtpServer.host", "smtpServer.from"}

    @pytest.mark.asyncio
    async def test_a_second_run_is_no_change_but_the_password_is_sent_again(self, tmp_path, smtp_env):
        """Requester, 2026-09-14: the password cannot be compared, so it is sent every run,
        and that is not a change — the job's check run must stay empty."""
        kc = FakeRealm({"bruteForceProtected": False})
        smtp = smtp_env()
        await converge(kc, a_declaration(tmp_path), smtp=smtp)

        second = await converge(kc, a_declaration(tmp_path), smtp=smtp)

        assert not second.changed
        assert second.smtp_password_applied
        assert len(smtp_puts(kc)) == 2

    @pytest.mark.asyncio
    async def test_without_authentication_a_second_run_writes_nothing(self, tmp_path, smtp_env):
        kc = FakeRealm({"bruteForceProtected": False})
        smtp = smtp_env(USER="", PASSWORD="")
        await converge(kc, a_declaration(tmp_path), smtp=smtp)

        second = await converge(kc, a_declaration(tmp_path), smtp=smtp)

        assert "password" not in smtp_puts(kc)[0]
        assert not second.changed and not second.smtp_password_applied
        assert len(smtp_puts(kc)) == 1

    @pytest.mark.asyncio
    async def test_a_changed_field_is_a_change_that_never_carries_the_password(self, tmp_path, smtp_env):
        kc = FakeRealm({"bruteForceProtected": False})
        await converge(kc, a_declaration(tmp_path), smtp=smtp_env())

        result = await converge(kc, a_declaration(tmp_path), smtp=smtp_env(HOST="smtp.other.test"))

        assert [(c.key, c.current, c.desired) for c in result.smtp] == [
            ("smtpServer.host", "smtp.example.test", "smtp.other.test")
        ]
        assert PASSWORD not in repr(result)

    @pytest.mark.asyncio
    async def test_a_host_without_a_sender_is_refused_before_any_write(self, tmp_path, smtp_env):
        kc = FakeRealm({"bruteForceProtected": True})

        with pytest.raises(PlatformDeclarationError, match="CELINE_KEYCLOAK_SMTP_FROM"):
            await converge(
                kc, a_declaration(tmp_path, "resetPasswordAllowed: true"), smtp=smtp_env(FROM="")
            )

        assert kc.writes == []

    @pytest.mark.asyncio
    async def test_authentication_without_a_password_is_refused(self, tmp_path, smtp_env):
        with pytest.raises(PlatformDeclarationError, match="CELINE_KEYCLOAK_SMTP_PASSWORD"):
            await converge(FakeRealm(), a_declaration(tmp_path), smtp=smtp_env(PASSWORD=""))

    @pytest.mark.asyncio
    @pytest.mark.parametrize("env", [None, "dev"])
    @pytest.mark.parametrize("dry_run", [True, False])
    async def test_the_report_never_contains_the_password(
        self, tmp_path, smtp_env, capsys, monkeypatch, env, dry_run
    ):
        from celine.policies.cli.keycloak.commands.bootstrap import _report_platform

        if env:
            monkeypatch.setenv("ENV", env)
        kc = FakeRealm({"bruteForceProtected": False})
        result = await converge(kc, a_declaration(tmp_path), smtp=smtp_env(), dry_run=dry_run)

        _report_platform(result, dry_run=dry_run)

        out = capsys.readouterr().out
        assert PASSWORD not in out
        assert "smtpServer.password: write-only" in out
        assert "smtpServer.host" in out


# ---------------------------------------------------------------------------
# Overrides from the environment (spindoxlabs/ds#36)
# ---------------------------------------------------------------------------


class TestTheEnvironmentOverridesListedKeys:
    """A deployment whose Keycloak differs from the image: stock themes, other lifespans."""

    def test_every_listed_key_is_a_key_bootstrap_owns_and_none_is_refused(self):
        from celine.policies.cli.keycloak.platform import ENV_OVERRIDABLE_SETTINGS, REALM_SETTING_TYPES

        assert set(ENV_OVERRIDABLE_SETTINGS) <= set(REALM_SETTING_TYPES)
        assert not set(ENV_OVERRIDABLE_SETTINGS) & set(REFUSED_REALM_SETTINGS)

    @pytest.mark.parametrize(
        "key", ["organizationsEnabled", "adminPermissionsEnabled", "internationalizationEnabled"]
    )
    def test_what_other_levels_depend_on_is_refused(self, key):
        with pytest.raises(PlatformDeclarationError, match="not an overridable"):
            load_platform(PLATFORM_YAML, environ={env_override_name(key): "false"})

    @pytest.mark.parametrize(
        ("key", "name"),
        [
            ("loginTheme", "CELINE_KEYCLOAK_PLATFORM_LOGIN_THEME"),
            ("accessTokenLifespanForImplicitFlow", "CELINE_KEYCLOAK_PLATFORM_ACCESS_TOKEN_LIFESPAN_FOR_IMPLICIT_FLOW"),
        ],
    )
    def test_the_variable_is_the_key_in_upper_snake_case(self, key, name):
        assert env_override_name(key) == name

    def test_unset_or_empty_keeps_the_declared_value(self):
        declaration = load_platform(PLATFORM_YAML, environ={"CELINE_KEYCLOAK_PLATFORM_LOGIN_THEME": ""})
        assert declaration.realm_settings["loginTheme"] == "rec"
        assert declaration.sources["loginTheme"] == str(PLATFORM_YAML)

    def test_null_drops_the_key_so_bootstrap_leaves_it_alone(self):
        declaration = load_platform(
            PLATFORM_YAML,
            environ={"CELINE_KEYCLOAK_PLATFORM_LOGIN_THEME": "null", "CELINE_KEYCLOAK_PLATFORM_EMAIL_THEME": "null"},
        )
        assert "loginTheme" not in declaration.realm_settings
        assert "emailTheme" not in declaration.sources

    @pytest.mark.parametrize(
        ("name", "raw", "key", "value"),
        [
            ("CELINE_KEYCLOAK_PLATFORM_LOGIN_THEME", "keycloak.v2", "loginTheme", "keycloak.v2"),
            ("CELINE_KEYCLOAK_PLATFORM_REGISTRATION_ALLOWED", "True", "registrationAllowed", True),
            ("CELINE_KEYCLOAK_PLATFORM_ACCESS_TOKEN_LIFESPAN", "300", "accessTokenLifespan", 300),
            ("CELINE_KEYCLOAK_PLATFORM_SUPPORTED_LOCALES", "it, en", "supportedLocales", ["it", "en"]),
        ],
    )
    def test_a_value_replaces_the_declared_one_and_names_its_source(self, name, raw, key, value):
        declaration = load_platform(PLATFORM_YAML, environ={name: raw})
        assert declaration.realm_settings[key] == value
        assert declaration.sources[key] == name

    def test_it_wins_over_an_overlay(self, tmp_path):
        overlay = write(tmp_path, "overlay.yaml", "realm_settings:\n  supportedLocales: [it, en]\n")
        declaration = load_platform(
            PLATFORM_YAML, [overlay], environ={"CELINE_KEYCLOAK_PLATFORM_SUPPORTED_LOCALES": "it,es"}
        )
        assert declaration.realm_settings["supportedLocales"] == ["it", "es"]

    @pytest.mark.parametrize(
        ("name", "raw"),
        [
            ("CELINE_KEYCLOAK_PLATFORM_REGISTRATION_ALLOWED", "yes"),
            ("CELINE_KEYCLOAK_PLATFORM_FAILURE_FACTOR", "-1"),
            ("CELINE_KEYCLOAK_PLATFORM_FAILURE_FACTOR", "five"),
            ("CELINE_KEYCLOAK_PLATFORM_SUPPORTED_LOCALES", "it,,en"),
        ],
    )
    def test_a_value_that_does_not_parse_is_refused_naming_the_variable(self, name, raw):
        with pytest.raises(PlatformDeclarationError, match=name):
            load_platform(PLATFORM_YAML, environ={name: raw})

    def test_the_merged_result_is_still_checked(self):
        with pytest.raises(PlatformDeclarationError, match="defaultLocale"):
            load_platform(PLATFORM_YAML, environ={"CELINE_KEYCLOAK_PLATFORM_SUPPORTED_LOCALES": "en"})

    @pytest.mark.asyncio
    async def test_a_stock_keycloak_bootstraps_with_the_themes_nulled(self):
        """The ds dev stack: stock Keycloak, no `rec`, and nothing written for the themes."""
        declaration = load_platform(
            PLATFORM_YAML,
            environ={"CELINE_KEYCLOAK_PLATFORM_LOGIN_THEME": "null", "CELINE_KEYCLOAK_PLATFORM_EMAIL_THEME": "null"},
        )
        kc = FakeRealm(themes={"login": ["keycloak", "keycloak.v2"], "email": ["keycloak"]})

        await converge(kc, declaration)

        assert not any({"loginTheme", "emailTheme"} & set(put) for put in kc.puts)

    @pytest.mark.asyncio
    async def test_an_overridden_theme_is_still_checked_against_the_server(self):
        declaration = load_platform(PLATFORM_YAML, environ={"CELINE_KEYCLOAK_PLATFORM_LOGIN_THEME": "custom"})
        kc = FakeRealm()

        with pytest.raises(PlatformDeclarationError, match="custom"):
            await converge(kc, declaration)
        assert kc.writes == []
