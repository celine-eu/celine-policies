"""Who may call the provisioning service: onboarding, and nobody else.

`svc-provisioning` holds realm-wide administration, and every `provisioning.*`
scope is a way of asking it to use that. **Onboarding is the single point of
access** (requester, 2026-09-14: "the least open the better, provisioning.* is
reserved and only onboarding have it"). A component that wants a participant's
account changed, or an email sent, goes through onboarding rather than holding a
grant of its own.

Checked over the base file **and** the ds-host overlay, because an overlay may
add grants to a client; and over default scopes, optional scopes and explicit
audiences, because an optional scope is still a scope a token can ask for.

`svc-community` is named on its own: it held `provisioning.participants.write`
as an optional scope for one working day before this decision reversed it.
"""

from __future__ import annotations

from pathlib import Path

from celine.policies.cli.keycloak.models import ClientConfig, KeycloakConfig

ROOT = Path(__file__).resolve().parents[1]
CLIENTS_YAML = ROOT / "clients.yaml"
DS_HOST_YAML = ROOT / "clients.ds-host.yaml"

OWNER = "svc-provisioning"
SOLE_CALLER = "svc-onboarding"


def _merged() -> KeycloakConfig:
    return KeycloakConfig.from_yaml_files([CLIENTS_YAML, DS_HOST_YAML], complete=False)


def _provisioning_scopes(client: ClientConfig) -> set[str]:
    return {
        s
        for s in set(client.default_scopes) | set(client.optional_scopes)
        if s.startswith("provisioning.")
    }


def _client(config: KeycloakConfig, client_id: str) -> ClientConfig:
    return next(c for c in config.clients if c.client_id == client_id)


def test_only_onboarding_holds_a_provisioning_scope():
    """Every holder of any `provisioning.*` scope other than the service itself."""
    config = _merged()

    holders = {
        c.client_id
        for c in config.clients
        if c.client_id != OWNER and _provisioning_scopes(c)
    }

    assert holders == {SOLE_CALLER}


def test_onboarding_holds_the_participant_write_scope_and_nothing_wider():
    """Not `.admin`, which satisfies every provisioning scope, and not
    `.reconcile`, which sweeps a whole community."""
    onboarding = _client(_merged(), SOLE_CALLER)

    assert _provisioning_scopes(onboarding) == {"provisioning.participants.write"}


def test_the_base_file_alone_says_the_same():
    """The overlay must not be what makes the posture hold."""
    config = KeycloakConfig.from_yaml(CLIENTS_YAML)

    holders = {
        c.client_id
        for c in config.clients
        if c.client_id != OWNER and _provisioning_scopes(c)
    }

    assert holders == {SOLE_CALLER}


def test_the_service_owns_the_family_and_holds_only_its_own_admin():
    config = _merged()

    assert config.build_prefix_to_client_map()["provisioning"] == OWNER
    assert _provisioning_scopes(_client(config, OWNER)) == {"provisioning.admin"}


def test_svc_community_holds_no_provisioning_scope():
    """Reverted 2026-09-14. The manager dashboard does not call the provisioning
    service; onboarding is the single point of access."""
    community = _client(_merged(), "svc-community")

    assert _provisioning_scopes(community) == set()
    # Its one optional scope is onboarding's, which is how it reaches the
    # provisioning service instead.
    assert community.optional_scopes == ["onboarding.members.invite"]


def test_nobody_else_gets_a_token_addressed_to_the_service():
    """An audience onto `svc-provisioning` is derived from a provisioning scope,
    or declared by hand in `extra_audiences`. Either way, only onboarding."""
    config = _merged()
    prefix_map = config.build_prefix_to_client_map()

    addressed = {
        c.client_id
        for c in config.clients
        if c.client_id != OWNER and OWNER in c.desired_audiences(prefix_map)
    }

    assert addressed == {SOLE_CALLER}


def test_svc_community_holds_no_keycloak_right():
    community = _client(_merged(), "svc-community")

    assert community.admin_permissions is None
    assert community.realm_management_roles == []
