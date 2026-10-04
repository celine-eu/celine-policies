"""The platform admin's second factor, as `bootstrap` converges it (REQ-0015, ADR-0013).

Against `keycloak_flows_fake.FlowsFake`, which answers the flow API the way Keycloak 26.7.3
does. Every test converges, then plans again: a second run must find nothing.
"""

from __future__ import annotations

from typing import Any

import pytest

from celine.policies.cli.keycloak.admin_mfa import (
    ADMIN_MFA_FLOW,
    apply_admin_mfa,
    desired_flow,
    flatten,
    plan_admin_mfa,
)
from celine.policies.cli.keycloak.platform import PlatformDeclarationError, destructive
from celine.policies.cli.keycloak.settings import KeycloakSettings
from keycloak_flows_fake import FlowsFake

ROLE = "platform-admin"
RETIRED = ("admin", "manager", "editor", "viewer")


class Realm(FlowsFake):
    def __init__(self, **kwargs: Any):
        self.realm: dict[str, Any] = {}
        self.writes: list[tuple] = []
        self.init_flows(**kwargs)

    async def get_realm_settings(self):
        return dict(self.realm)

    async def update_realm_settings(self, settings):
        self.writes.append(("realm", tuple(sorted(settings))))
        self.realm.update(settings)


async def plan(kc: Realm, *, required: bool = True, **kwargs):
    return await plan_admin_mfa(
        kc, required=required, role=ROLE, retired_roles=RETIRED,
        browser_flow=kc.realm.get("browserFlow"), **kwargs,
    )


async def converge(kc: Realm, **kwargs):
    first = await plan(kc, **kwargs)
    await apply_admin_mfa(kc, first)
    again = await plan(kc, **kwargs)
    assert again.changes == [], again.changes
    return first


def expected_shape(role: str = ROLE, **kwargs) -> list[tuple[int, str, str]]:
    return [(s.level, s.name, s.requirement) for s, _ in flatten(desired_flow(role, **kwargs))]


def build_old_import_flow(kc: Realm, role: str = "admin") -> None:
    """The flow infra's realm import declared: the same shape, conditioned on `admin`."""

    def build(parent, nodes):
        for node in nodes:
            if node.is_flow:
                kc.add(parent, sub=node.name, requirement=node.requirement)
                build(node.name, node.children)
            else:
                kc.add(parent, node.name, requirement=node.requirement,
                       config=dict(node.config) or None, config_alias=node.config_alias)

    kc.new_flow(ADMIN_MFA_FLOW)
    build(ADMIN_MFA_FLOW, desired_flow(role))


class TestOutsideDevItIsOn:
    def test_by_default_unless_env_is_exactly_dev(self, monkeypatch):
        """@verifies REQ-0015"""
        assert KeycloakSettings().admin_mfa is True
        for env in ("prod", "staging", "development", "test"):
            monkeypatch.setenv("ENV", env)
            assert KeycloakSettings().admin_mfa is True, env
        monkeypatch.setenv("ENV", "dev")
        assert KeycloakSettings().admin_mfa is False
        monkeypatch.setenv("CELINE_KEYCLOAK_ADMIN_MFA_REQUIRED", "true")
        assert KeycloakSettings().admin_mfa is True
        monkeypatch.setenv("CELINE_KEYCLOAK_ADMIN_MFA_REQUIRED", "")
        assert KeycloakSettings().admin_mfa is False


class TestConvergingFromAnyStart:
    @pytest.mark.asyncio
    async def test_no_flow_it_is_built_and_bound(self):
        """@verifies REQ-0015"""
        kc = Realm()

        first = await converge(kc)

        assert kc.flow_shape(ADMIN_MFA_FLOW) == expected_shape()
        assert kc.realm["browserFlow"] == ADMIN_MFA_FLOW
        assert kc.config_of(ADMIN_MFA_FLOW, "conditional-user-role") == {"condUserRole": ROLE, "negate": "false"}
        assert kc.config_of(ADMIN_MFA_FLOW, "conditional-credential") == {
            "credentials": "webauthn-passwordless", "included": "false"}
        assert kc.config_of(ADMIN_MFA_FLOW, "conditional-sub-flow-executed") == {
            "flow_to_check": f"{ADMIN_MFA_FLOW} configured", "check_result": "not-executed"}
        assert not any(destructive(c) for c in first.changes)

    @pytest.mark.asyncio
    async def test_the_import_flow_on_the_retired_role_is_corrected_in_place(self):
        """The flow infra's import declared names `admin`, which bootstrap deletes.

        @verifies REQ-0015
        """
        kc = Realm()
        build_old_import_flow(kc, role="admin")
        kc.realm["browserFlow"] = ADMIN_MFA_FLOW
        flows_before = set(kc.flows)

        first = await converge(kc)

        assert [c.key for c in first.changes] == [
            f"authenticatorConfig {ADMIN_MFA_FLOW}-admin-role.condUserRole"
        ]
        assert set(kc.flows) == flows_before  # not rebuilt
        assert kc.config_of(ADMIN_MFA_FLOW, "conditional-user-role")["condUserRole"] == ROLE

    @pytest.mark.asyncio
    async def test_a_flow_of_another_shape_is_rebuilt_even_while_bound(self):
        """Keycloak refuses to delete the bound browser flow: it is unbound for the rebuild.

        @verifies REQ-0015
        """
        kc = Realm()
        kc.new_flow(ADMIN_MFA_FLOW)
        kc.add(ADMIN_MFA_FLOW, "auth-username-password-form", requirement="REQUIRED")
        kc.add(ADMIN_MFA_FLOW, sub="otp", requirement="CONDITIONAL")
        kc.add("otp", "conditional-user-role", requirement="REQUIRED",
               config={"condUserRole": "admin"}, config_alias="old-role")
        kc.add("otp", "auth-otp-form", requirement="ALTERNATIVE")
        kc.realm["browserFlow"] = ADMIN_MFA_FLOW

        first = await converge(kc)

        assert ("delete-flow", ADMIN_MFA_FLOW) in kc.writes
        assert any(c.desired == "rebuilt" for c in first.changes)
        assert kc.flow_shape(ADMIN_MFA_FLOW) == expected_shape()
        assert kc.realm["browserFlow"] == ADMIN_MFA_FLOW
        assert "otp" not in kc.flows

    @pytest.mark.asyncio
    async def test_a_disabled_required_action_is_enabled(self):
        """@verifies REQ-0015"""
        kc = Realm(required_actions={"CONFIGURE_TOTP": False, "CONFIGURE_RECOVERY_AUTHN_CODES": True})

        await converge(kc)

        assert kc.required_actions["CONFIGURE_TOTP"] is True

    @pytest.mark.asyncio
    async def test_a_condition_on_a_retired_role_in_another_flow_is_repointed(self):
        """@verifies REQ-0015"""
        kc = Realm()
        kc.new_flow("custom")
        kc.add("custom", "conditional-user-role", requirement="REQUIRED",
               config={"condUserRole": "manager", "negate": "false"}, config_alias="custom-role")

        await converge(kc)

        assert kc.config_of("custom", "conditional-user-role") == {"condUserRole": ROLE, "negate": "false"}


class TestItRefusesBeforeAnyWrite:
    @pytest.mark.asyncio
    async def test_an_authenticator_the_server_does_not_list(self):
        """An unknown provider id fails every browser sign-in, for every user.

        @verifies REQ-0015
        """
        kc = Realm(providers={"auth-cookie"})

        with pytest.raises(PlatformDeclarationError, match="every browser sign-in"):
            await plan(kc)
        assert kc.writes == []

    @pytest.mark.asyncio
    async def test_an_unregistered_required_action(self):
        """@verifies REQ-0015"""
        kc = Realm(required_actions={"CONFIGURE_TOTP": True})

        with pytest.raises(PlatformDeclarationError, match="CONFIGURE_RECOVERY_AUTHN_CODES"):
            await plan(kc)
        assert kc.writes == []


class TestOff:
    @pytest.mark.asyncio
    async def test_keycloaks_own_browser_flow_is_bound_and_the_custom_flow_kept(self):
        """@verifies REQ-0015"""
        kc = Realm()
        await converge(kc)

        off = await converge(kc, required=False)

        assert kc.realm["browserFlow"] == "browser"
        assert ADMIN_MFA_FLOW in kc.flows
        assert [c.key for c in off.changes] == ["browserFlow"]
        assert destructive(off.changes[0])

    @pytest.mark.asyncio
    async def test_on_a_realm_that_never_had_it_nothing_changes(self):
        """Dev: Keycloak's own flow, bound by Keycloak itself, is left as it is."""
        kc = Realm()

        off = await converge(kc, required=False)

        assert off.changes == []
        assert kc.writes == []


class TestTheMasterShape:
    def test_it_has_no_organization_step(self):
        """@verifies REQ-0016"""
        names = [name for _, name, _ in expected_shape("admin", organization=False)]
        assert not any("organization" in n for n in names)
        assert names[:3] == ["auth-cookie", "auth-spnego", "identity-provider-redirector"]
        with_org = expected_shape("admin")
        assert len(with_org) - len(expected_shape("admin", organization=False)) == 4
