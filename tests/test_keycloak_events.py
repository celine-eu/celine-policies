"""The realm's event recording, as `bootstrap` converges it (REQ-0024).

Against `keycloak_events_fake.EventsFake`, which answers `GET/PUT …/events/config` the way
Keycloak's source does. Every converging test plans again after the write: a second run must
find nothing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from keycloak_events_fake import DEFAULT_EVENT_TYPES, EventsFake
from keycloak_flows_fake import MasterFake
from test_bootstrap_job import JobRealm, converged
from test_platform_declaration import PLATFORM_YAML

import celine.policies.cli.keycloak.commands.bootstrap as bootstrap_module
from celine.policies.cli.keycloak.events import (
    DEFAULT_EVENTS_EXPIRATION,
    EVENTS_SOURCE,
    REQUIRED_EVENT_TYPES,
    apply_events,
    plan_events,
)
from celine.policies.cli.keycloak.platform import (
    PlatformDeclarationError,
    PlatformResult,
    destructive,
    load_platform,
)
from celine.policies.cli.keycloak.settings import KeycloakSettings

YEAR = 365 * 24 * 3600


class Realm(EventsFake):
    def __init__(self, **stored: Any):
        self.writes: list[tuple] = []
        self.init_events(**stored)


def declared(environ: dict[str, str] | None = None, overlays: tuple[Path, ...] = ()):
    return load_platform(PLATFORM_YAML, overlays, environ or {}).events


async def converge(kc: Realm, **kwargs):
    events = kwargs.pop("events", None) or declared()
    first = await plan_events(kc, events, enabled=kwargs.pop("enabled", True))
    await apply_events(kc, first)
    again = await plan_events(kc, events, enabled=True)
    assert again.changes == [], again.changes
    return first


# ---------------------------------------------------------------------------
# The switch
# ---------------------------------------------------------------------------


class TestOutsideDevItIsOn:
    def test_by_default_unless_env_is_exactly_dev(self, monkeypatch):
        """@verifies REQ-0024"""
        assert KeycloakSettings().events_recorded is True
        for env in ("prod", "staging", "preprod", "development"):
            monkeypatch.setenv("ENV", env)
            assert KeycloakSettings().events_recorded is True, env
        monkeypatch.setenv("ENV", "dev")
        assert KeycloakSettings().events_recorded is False
        monkeypatch.setenv("CELINE_KEYCLOAK_EVENTS_ENABLED", "true")
        assert KeycloakSettings().events_recorded is True
        monkeypatch.setenv("CELINE_KEYCLOAK_EVENTS_ENABLED", "")
        assert KeycloakSettings().events_recorded is False
        monkeypatch.delenv("ENV")
        monkeypatch.setenv("CELINE_KEYCLOAK_EVENTS_ENABLED", "false")
        assert KeycloakSettings().events_recorded is False

    def test_the_switch_survives_the_cli_overrides(self, monkeypatch):
        monkeypatch.setenv("CELINE_KEYCLOAK_EVENTS_ENABLED", "false")
        assert KeycloakSettings().with_overrides(realm="other").events_recorded is False


# ---------------------------------------------------------------------------
# The declaration
# ---------------------------------------------------------------------------


class TestTheDeclaration:
    def test_the_image_declares_the_audit_types_a_year_and_no_admin_details(self):
        """@verifies REQ-0024"""
        events = declared()
        assert {"IMPERSONATE", "LOGIN", "LOGIN_ERROR"} <= set(events.required_types)
        assert set(events.required_types) == set(REQUIRED_EVENT_TYPES)
        assert events.expiration == DEFAULT_EVENTS_EXPIRATION == YEAR
        assert events.admin_details is False

    def test_the_expiration_takes_an_override(self):
        """@verifies REQ-0024"""
        name = "CELINE_KEYCLOAK_PLATFORM_EVENTS_EXPIRATION"
        decl = load_platform(PLATFORM_YAML, (), {name: "2592000"})
        assert decl.events.expiration == 2592000
        assert decl.sources["events.expiration"] == name
        assert load_platform(PLATFORM_YAML, (), {name: "null"}).events.expiration is None
        for bad in ("a year", "-1", "1.5"):
            with pytest.raises(PlatformDeclarationError, match=name):
                load_platform(PLATFORM_YAML, (), {name: bad})

    @pytest.mark.parametrize(
        ("block", "match"),
        [
            ("events:\n  expiration: -1\n", "events.expiration"),
            ("events:\n  expiration: true\n", "events.expiration"),
            ("events:\n  admin_details: 'no'\n", "events.admin_details"),
            ("events:\n  user_event_types: []\n", "events.user_event_types"),
            ("events:\n  user_event_types: [LOGIN, LOGIN]\n", "events.user_event_types"),
            ("events:\n  user_event_types: [login]\n", "events.user_event_types"),
            ("events:\n  user_event_types: [LOGIN]\n", "IMPERSONATE"),
            ("events:\n  listeners: [email]\n", "listeners"),
        ],
    )
    def test_a_wrong_block_is_refused(self, tmp_path, block, match):
        path = tmp_path / "platform.yaml"
        data = yaml.safe_load(PLATFORM_YAML.read_text())
        data["events"] = yaml.safe_load(block)["events"]
        path.write_text(yaml.safe_dump(data))
        with pytest.raises(PlatformDeclarationError, match=match):
            load_platform(path)

    def test_an_overlay_may_not_change_it(self, tmp_path):
        overlay = tmp_path / "overlay.yaml"
        overlay.write_text("events:\n  expiration: 60\n")
        with pytest.raises(PlatformDeclarationError, match="events"):
            load_platform(PLATFORM_YAML, (overlay,))


# ---------------------------------------------------------------------------
# Converging
# ---------------------------------------------------------------------------


class TestConvergingFromAnyStart:
    @pytest.mark.asyncio
    async def test_a_new_realm_records_user_and_admin_events_with_an_expiry(self):
        """Keycloak's own default types already hold the required ones: no list is written,
        so the realm keeps following Keycloak's defaults.

        @verifies REQ-0024
        """
        kc = Realm()

        first = await converge(kc)

        assert kc.events["eventsEnabled"] is True
        assert kc.events["adminEventsEnabled"] is True
        assert kc.events["adminEventsDetailsEnabled"] is False
        assert kc.events["eventsExpiration"] == YEAR
        assert kc.events["eventsListeners"] == ["jboss-logging"]
        assert kc.events["enabledEventTypes"] == []
        assert "enabledEventTypes" not in kc.events_puts[0]
        assert {c.key for c in first.changes} == {
            "events.eventsEnabled", "events.adminEventsEnabled", "events.eventsExpiration"}
        assert {c.source for c in first.changes if c.key.endswith("Enabled")} == {EVENTS_SOURCE}
        assert not any(destructive(c) for c in first.changes)

    @pytest.mark.asyncio
    async def test_a_narrowed_list_gets_the_required_types_and_keeps_its_own(self):
        """@verifies REQ-0024"""
        kc = Realm(enabledEventTypes=["LOGIN", "UPDATE_PASSWORD"])

        first = await converge(kc)

        assert set(kc.events["enabledEventTypes"]) == {"UPDATE_PASSWORD", *REQUIRED_EVENT_TYPES}
        change = next(c for c in first.changes if c.key == "events.enabledEventTypes")
        assert not destructive(change)

    @pytest.mark.asyncio
    async def test_the_listeners_are_kept_as_they_are(self):
        """@verifies REQ-0024"""
        kc = Realm(eventsListeners=["jboss-logging", "email"])

        await converge(kc)

        assert kc.events_puts[0]["eventsListeners"] == ["jboss-logging", "email"]
        assert kc.events["eventsListeners"] == ["jboss-logging", "email"]

    @pytest.mark.asyncio
    async def test_already_right_nothing_is_written(self):
        """@verifies REQ-0024"""
        kc = Realm(eventsEnabled=True, adminEventsEnabled=True, eventsExpiration=YEAR)

        plan = await plan_events(kc, declared(), enabled=True)
        await apply_events(kc, plan)

        assert plan.changes == []
        assert kc.writes == []

    @pytest.mark.asyncio
    async def test_a_null_expiration_keeps_the_realms_own(self):
        """Keycloak resets an expiration the body leaves out to 0 ("never"), so the realm's
        own value is sent back.

        @verifies REQ-0024
        """
        kc = Realm(eventsExpiration=600)
        events = declared({"CELINE_KEYCLOAK_PLATFORM_EVENTS_EXPIRATION": "null"})

        first = await converge(kc, events=events)

        assert kc.events["eventsExpiration"] == 600
        assert "events.eventsExpiration" not in {c.key for c in first.changes}

    @pytest.mark.asyncio
    async def test_admin_details_turned_off_is_destructive(self):
        """@verifies REQ-0024"""
        kc = Realm(eventsEnabled=True, adminEventsEnabled=True, eventsExpiration=YEAR,
                   adminEventsDetailsEnabled=True)

        first = await converge(kc)

        assert [c.key for c in first.changes] == ["events.adminEventsDetailsEnabled"]
        assert destructive(first.changes[0])
        assert kc.events["adminEventsDetailsEnabled"] is False

    @pytest.mark.asyncio
    async def test_a_write_that_does_not_take_is_an_error(self):
        kc = Realm()
        kc.events_sticky = False
        plan = await plan_events(kc, declared(), enabled=True)

        with pytest.raises(PlatformDeclarationError, match="eventsEnabled"):
            await apply_events(kc, plan)


class TestOff:
    @pytest.mark.asyncio
    async def test_off_the_realms_events_are_left_alone(self):
        """Not turned off: off means bootstrap does not manage them.

        @verifies REQ-0024
        """
        kc = Realm(eventsEnabled=True, adminEventsEnabled=True)

        plan = await plan_events(kc, declared(), enabled=False)
        await apply_events(kc, plan)

        assert plan.changes == []
        assert plan.skipped
        assert kc.writes == []
        assert kc.events["eventsEnabled"] is True


# ---------------------------------------------------------------------------
# The whole run
# ---------------------------------------------------------------------------


class EventsRealm(EventsFake, JobRealm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.init_events()


async def run(settings, target, monkeypatch, **kwargs):
    master = MasterFake()
    monkeypatch.setattr(
        bootstrap_module, "KeycloakAdminClient",
        lambda s: master if s.realm == "master" else target,
    )
    args = {
        "declaration": load_platform(PLATFORM_YAML), "client_id": "celine-admin-cli",
        "manage_admin_client": True, "dry_run": False, "admin_mfa": settings.admin_mfa,
        "harden_master": settings.master_hardened, "events": settings.events_recorded,
    }
    args.update(kwargs)
    result, _ = await bootstrap_module._async_bootstrap(settings=settings, **args)
    return result, master


def run_settings(**kwargs) -> KeycloakSettings:
    defaults = {
        "base_url": "http://kc.internal", "realm": "celine", "admin_user": "admin",
        "admin_password": "admin", "bootstrap_client_secret": "c" * 40,
    }
    defaults.update(kwargs)
    return KeycloakSettings(**defaults)


class TestTheRun:
    @pytest.mark.asyncio
    async def test_outside_dev_the_target_realm_records_events_and_master_is_not_touched(self, monkeypatch):
        """Master's events stay out of this change.

        @verifies REQ-0024
        """
        target = EventsRealm(converged(), roles={"platform-admin"})

        result, master = await run(run_settings(), target, monkeypatch)

        assert target.events["eventsEnabled"] is True
        assert target.events["adminEventsEnabled"] is True
        assert result.events
        assert not hasattr(master, "events")
        again, _ = await run(run_settings(), target, monkeypatch, dry_run=True)
        assert again.events == []

    @pytest.mark.asyncio
    async def test_a_dry_run_plans_without_writing(self, monkeypatch):
        """@verifies REQ-0024"""
        target = EventsRealm(converged(), roles={"platform-admin"})

        result, _ = await run(run_settings(), target, monkeypatch, dry_run=True)

        assert result.events and result.changed
        assert target.events_puts == []

    @pytest.mark.asyncio
    async def test_turning_admin_details_off_needs_the_flag_outside_dev(self, monkeypatch):
        target = EventsRealm(converged(), roles={"platform-admin"})
        target.events.update(eventsEnabled=True, adminEventsEnabled=True,
                             eventsExpiration=YEAR, adminEventsDetailsEnabled=True)

        with pytest.raises(PlatformDeclarationError, match="adminEventsDetailsEnabled"):
            await run(run_settings(), target, monkeypatch, allow_destructive=False)
        assert target.events_puts == []

    @pytest.mark.asyncio
    async def test_dev_leaves_the_events_alone(self, monkeypatch):
        """@verifies REQ-0024"""
        target = EventsRealm(converged(), roles={"platform-admin"})

        result, _ = await run(run_settings(env="dev", bootstrap_client_secret=None), target, monkeypatch)

        assert target.events_puts == []
        assert result.events == []
        assert result.events_skipped


class TestTheReport:
    def test_each_outcome_has_a_line(self, capsys):
        """@verifies REQ-0024"""
        bootstrap_module._report_platform(PlatformResult(), dry_run=False)
        assert "events: no change" in capsys.readouterr().out

        bootstrap_module._report_platform(PlatformResult(events_skipped="ENV=dev"), dry_run=False)
        assert "events: left alone (ENV=dev)" in capsys.readouterr().out

        from celine.policies.cli.keycloak.platform import SettingChange

        changed = PlatformResult(events=[SettingChange("events.eventsEnabled", False, True, EVENTS_SOURCE)])
        bootstrap_module._report_platform(changed, dry_run=True)
        assert "events.eventsEnabled: False -> True" in capsys.readouterr().out


def test_the_fake_reports_keycloaks_defaults_when_no_list_is_stored():
    """Guards the fake: the required types are among Keycloak's defaults."""
    assert set(REQUIRED_EVENT_TYPES) <= set(DEFAULT_EVENT_TYPES)


def test_the_command_passes_the_switch(monkeypatch):
    """@verifies REQ-0024"""
    from typer.testing import CliRunner

    from celine.policies.cli.main import app

    seen: dict[str, Any] = {}

    async def fake(**kwargs):
        seen.update(kwargs)
        return PlatformResult(), ("", False)

    monkeypatch.setattr(bootstrap_module, "_async_bootstrap", fake)
    monkeypatch.setenv("CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_SECRET", "b" * 40)
    args = ["keycloak", "bootstrap", str(PLATFORM_YAML), "-u", "http://kc"]

    CliRunner().invoke(app, args)
    assert seen["events"] is True
    monkeypatch.setenv("ENV", "dev")
    CliRunner().invoke(app, args)
    assert seen["events"] is False
