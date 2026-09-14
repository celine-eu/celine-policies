"""Tests for the REC onboarding console scope family and its clients.

The onboarding console authorises REC operators by Keycloak *organization* +
*org group* membership, not by scope — so what these tests guard is the other
half: that service accounts and the CLI have a scope vocabulary to state intent
with, that `onboarding.*` has exactly one owner, and that a browser token issued
through oauth2-proxy will carry the audience the console validates.
"""

from __future__ import annotations

from pathlib import Path

from celine.policies.cli.keycloak.models import KeycloakConfig

CLIENTS_YAML = Path(__file__).resolve().parents[1] / "clients.yaml"
DS_HOST_YAML = Path(__file__).resolve().parents[1] / "clients.ds-host.yaml"


def _config() -> KeycloakConfig:
    return KeycloakConfig.from_yaml(CLIENTS_YAML)


# ---------------------------------------------------------------------------
# Scope family
# ---------------------------------------------------------------------------

# Every capability the console enforces. Kept as a literal list rather than a
# prefix match so that deleting a scope fails here instead of silently removing
# a capability the policy still references.
EXPECTED_SCOPES = {
    "onboarding.admin",
    "onboarding.recs.read",
    "onboarding.submissions.read",
    "onboarding.submissions.reveal",
    "onboarding.submissions.write",
    "onboarding.submissions.review",
    "onboarding.submissions.purge",
    "onboarding.enablement.retry",
    "onboarding.enablement.revoke",
    "onboarding.audit.read",
    "onboarding.export",
}


class TestOnboardingScopes:
    def test_all_capabilities_are_defined(self):
        defined = _config().get_scope_names()
        assert EXPECTED_SCOPES <= defined

    def test_no_undeclared_onboarding_scopes(self):
        """A scope nobody planned for is either a typo or an undocumented grant."""
        defined = {s for s in _config().get_scope_names() if s.startswith("onboarding.")}
        assert defined == EXPECTED_SCOPES

    def test_every_scope_has_a_description(self):
        for scope in _config().scopes:
            if scope.name.startswith("onboarding."):
                assert scope.description, f"{scope.name} has no description"

    def test_destructive_capabilities_are_separate_scopes(self):
        """Purge and revoke must not be reachable through the review grant.

        Rejecting somebody is recoverable; erasing them, or revoking their
        credential, is not. A deployment must be able to grant one without the
        other — which it cannot do if they share a scope.
        """
        defined = _config().get_scope_names()
        assert "onboarding.submissions.purge" in defined
        assert "onboarding.enablement.revoke" in defined
        assert "onboarding.submissions.purge" != "onboarding.submissions.review"


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------


class TestOnboardingClients:
    def test_svc_onboarding_owns_the_scope_family(self):
        config = _config()
        assert "svc-onboarding" in config.get_client_ids()
        assert config.build_prefix_to_client_map()["onboarding"] == "svc-onboarding"

    def test_svc_onboarding_holds_its_own_admin_scope(self):
        onb = next(c for c in _config().clients if c.client_id == "svc-onboarding")
        assert onb.scopes_prefix == "onboarding"
        assert "onboarding.admin" in onb.default_scopes

    def test_svc_onboarding_calls_exactly_two_other_services(self):
        """It used to reference only its own scopes and derive no mapper at all.

        `svc-provisioning` for a participant's login, instead of reaching
        Keycloak itself (ADR-0007). `svc-rec-registry` because this service
        registers the member on approval, writes their dataspace DID onto that
        row, and reads back what each consenting DID holds for the POD export —
        three call sites that have existed in `../onboarding` all along and were
        **never granted**: measured on demo3 2026-09-12, every one of them
        answered `401`, because holding no `rec-registry.*` scope derives no
        audience onto `svc-rec-registry` and the registry refuses the token
        before it reads a scope. `ensure_member_did` never raises by design, so
        the symptom was a member who consents and exports nothing.

        A **third** audience appearing here means somebody widened what the
        public onboarding front door can call, and that is the thing to argue
        for. Note what is deliberately absent from the two it has:
        `rec-registry.import` and `.members.purge`, either of which would let
        the front door destroy a community.
        """
        config = _config()
        onb = next(c for c in config.clients if c.client_id == "svc-onboarding")
        assert onb.desired_audiences(config.build_prefix_to_client_map()) == {
            "svc-provisioning",
            "svc-rec-registry",
        }
        registry_scopes = {
            s for s in onb.default_scopes if s.startswith("rec-registry.")
        }
        assert registry_scopes == {
            "rec-registry.members.write",
            "rec-registry.lookup",
        }

    def test_user_tokens_will_carry_the_console_audience(self):
        """oauth2-proxy gets a mapper for every client with a scopes_prefix.

        This is the whole reason `svc-onboarding` is declared as a service client:
        without it, a REC operator's browser JWT has no `aud: svc-onboarding` and
        the console rejects it before any policy runs.
        """
        assert "svc-onboarding" in _config().get_service_client_ids()

    def test_cli_client_targets_the_console(self):
        config = _config()
        cli = next(c for c in config.clients if c.client_id == "svc-onboarding-cli")
        assert cli.scopes_prefix is None, "the CLI owns no scope family"
        assert "onboarding.admin" in cli.default_scopes
        assert cli.service_account_enabled is True
        assert "svc-onboarding" in cli.desired_audiences(
            config.build_prefix_to_client_map()
        )

    def test_admin_cli_can_reach_the_console(self):
        ccli = next(c for c in _config().clients if c.client_id == "celine-cli")
        assert "onboarding.admin" in ccli.default_scopes
        assert "svc-onboarding" in ccli.extra_audiences

    def test_outbound_dataspace_client_is_untouched(self):
        """`svc-ds-onboarding` stays the service's outbound identity.

        One service, two clients: `svc-onboarding` validates inbound audiences,
        `svc-ds-onboarding` authenticates outbound M2M to the dataspace. Renaming
        the latter would ripple through the ds deployment's env, so it does not
        acquire the `onboarding` prefix — and ds owns that client now, so what
        this asserts is that celine's overlay does not push it back inbound.
        """
        assert "svc-ds-onboarding" not in _config().get_client_ids(), (
            "the dataspace's clients are declared by ds — see clients.ds-host.yaml"
        )
        host = KeycloakConfig.from_yaml(DS_HOST_YAML)
        ds = next(c for c in host.clients if c.client_id == "svc-ds-onboarding")
        assert not any(s.startswith("onboarding.") for s in ds.default_scopes)
        assert "svc-onboarding" not in ds.extra_audiences

    def test_no_undefined_scope_references(self):
        assert _config().validate_scope_references() == []
