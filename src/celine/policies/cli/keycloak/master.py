"""The master realm, as `bootstrap` reaches and hardens it (REQ-0016, ADR-0014).

The master realm holds the Keycloak-wide administrator, the account that configures the
platform, and Keycloak is public. So, on every `bootstrap` run:

1. **Sign in to master as the dedicated client first** (`svc-celine-policies-bootstrap`,
   `client_credentials`, the secret a configured value). Only when that fails, as the
   master admin user.
2. **Converge that client**: confidential, service account only, the configured secret, and
   master's realm role `admin` (`BOOTSTRAP_MASTER_REALM_ROLES`; why that one, below).
3. **Switch to its token** for everything else.
4. **Outside dev, harden master**: brute-force detection with the platform realm's declared
   tuning, and a second factor for every master administrator (the browser flow of
   `admin_mfa`, conditioned on master's `admin` role, and `CONFIGURE_TOTP` on each admin who
   has no one-time code yet, which also closes the password grant).

Step 4 refuses any token but the bootstrap client's own, obtained and checked in this run
(`require_bootstrap_client`): an administrator's token could turn on the factor that cuts
that administrator off halfway through the run.

## Measured on Keycloak 26.7.3 (throwaway instance, 2026-10-04)

- A master client's secret is set by `PUT /clients/{id}` with `secret` in the representation.
- **The client needs master's `admin`, nothing narrower works.** `bootstrap` grants the admin
  CLI client its `realm-management` roles, and the platform realm has fine-grained admin
  permissions (v2) on (`adminPermissionsEnabled`, `platform.yaml`). In such a realm a master
  principal that is not a master `admin` gets 403 mapping any administration role, even holding
  every `<realm>-realm` role, and even as the client that created the realm. Without fine-grained
  permissions the `<realm>-realm` roles would do. So the client is as powerful as the admin user
  it replaces; what changes is that it cannot sign in through a browser, its secret is a
  configured value, and the person's account gets a second factor.
- A client holding `manage-users` cannot grant itself a role it does not hold (403).
- Master's own `browser` flow has no organization step.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from celine.policies.cli.keycloak.admin_mfa import (
    AdminMfaPlan,
    apply_admin_mfa,
    plan_admin_mfa,
)
from celine.policies.cli.keycloak.client import (
    MASTER_CLIENT,
    KeycloakAdminClient,
    KeycloakAuthError,
)
from celine.policies.cli.keycloak.platform import (
    PlatformDeclaration,
    PlatformDeclarationError,
    SettingChange,
    destructive,
    plan_realm_settings,
)

if TYPE_CHECKING:
    from celine.policies.cli.keycloak.settings import KeycloakSettings

MASTER_REALM = "master"
#: Master's own administrator role: what the KC_BOOTSTRAP_ADMIN user and `kc.sh
#: bootstrap-admin user` hold. The second factor is conditioned on it.
MASTER_ADMIN_ROLE = "admin"
#: The required action that makes a master admin enrol a one-time code, and that stops a
#: password grant ("Account is not fully set up") until they have.
CONFIGURE_TOTP = "CONFIGURE_TOTP"

#: Where each master change comes from, in a report.
BRUTE_FORCE_SOURCE = "CELINE_KEYCLOAK_BRUTE_FORCE_ENABLED (master)"
MFA_SOURCE = "CELINE_KEYCLOAK_ADMIN_MFA_REQUIRED (master)"
CLIENT_SOURCE = "CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_*"

#: The platform realm's brute-force tuning, which master takes from the same declaration.
BRUTE_FORCE_TUNING = (
    "permanentLockout",
    "failureFactor",
    "waitIncrementSeconds",
    "quickLoginCheckMilliSeconds",
    "minimumQuickLoginWaitSeconds",
    "maxFailureWaitSeconds",
)

#: Master realm roles the bootstrap client holds: `admin`, the only one that may grant
#: administration roles in a realm with fine-grained admin permissions (measured, above).
BOOTSTRAP_MASTER_REALM_ROLES = ("admin",)

#: The bootstrap client's flags. Anything else of the representation is left alone.
BOOTSTRAP_CLIENT_FLAGS: dict[str, Any] = {
    "enabled": True,
    "publicClient": False,
    "bearerOnly": False,
    "serviceAccountsEnabled": True,
    "standardFlowEnabled": False,
    "implicitFlowEnabled": False,
    "directAccessGrantsEnabled": False,
    "clientAuthenticatorType": "client-secret",
}


class MasterHardeningRefused(KeycloakAuthError):
    """The master hardening was asked to run on a token that is not the bootstrap client's."""


@dataclass
class BootstrapClientPlan:
    """What converging the bootstrap client would write."""

    client_id: str
    client: dict[str, Any] | None = None
    create: bool = False
    #: flag -> desired, for an existing client
    flags: dict[str, Any] = field(default_factory=dict)
    #: The secret differs from the configured one (never the value itself).
    secret: bool = False
    #: master realm role representations to grant
    roles: list[dict[str, Any]] = field(default_factory=list)
    #: Roles the client is to hold that the server does not have (refused before any write).
    unknown_roles: list[str] = field(default_factory=list)

    @property
    def changes(self) -> list[SettingChange]:
        out: list[SettingChange] = []
        if self.create:
            out.append(SettingChange(f"client {self.client_id}", None, "created", CLIENT_SOURCE))
        for key, value in self.flags.items():
            out.append(SettingChange(f"client {self.client_id}.{key}", (self.client or {}).get(key), value, CLIENT_SOURCE))
        if self.secret and not self.create:
            out.append(SettingChange(f"client {self.client_id}.secret", "<another>", "<configured>", CLIENT_SOURCE))
        if self.roles:
            names = sorted(r["name"] for r in self.roles)
            out.append(SettingChange(f"client {self.client_id} realm roles", None, names, CLIENT_SOURCE))
        return out


async def plan_bootstrap_client(
    master: KeycloakAdminClient,
    *,
    client_id: str,
    secret: str,
    signed_in_as_client: bool,
) -> BootstrapClientPlan:
    """Read master and plan the client. Writes nothing.

    `signed_in_as_client`: this session is the client itself, so the secret is known to match.
    """
    plan = BootstrapClientPlan(client_id=client_id)
    client = await master.get_client_by_client_id(client_id)
    held: set[str] = set()
    if client is None:
        plan.create = True
        plan.secret = True
    else:
        full = await master.get_client(client["id"])
        plan.client = full
        plan.flags = {k: v for k, v in BOOTSTRAP_CLIENT_FLAGS.items() if full.get(k) != v}
        if not signed_in_as_client:
            plan.secret = (await master.get_client_secret(full["id"])) != secret
        if full.get("serviceAccountsEnabled"):
            sa_user = await master.get_service_account_user(full["id"])
            held = await master.get_user_realm_role_names(sa_user["id"])

    for name in BOOTSTRAP_MASTER_REALM_ROLES:
        if name in held:
            continue
        role = await master.get_realm_role(name)
        if role is None:
            plan.unknown_roles.append(name)
        else:
            plan.roles.append({"id": role["id"], "name": role["name"]})
    if plan.unknown_roles:
        raise PlatformDeclarationError(
            f"the bootstrap client {client_id} is to hold the master realm roles "
            f"{plan.unknown_roles}, which this Keycloak does not have"
        )
    return plan


async def apply_bootstrap_client(
    master: KeycloakAdminClient, plan: BootstrapClientPlan, *, secret: str
) -> None:
    """Write `plan`: the client, its flags and secret, then its roles."""
    if plan.create:
        await master.create_client(
            client_id=plan.client_id,
            name=plan.client_id,
            description="celine-policies keycloak bootstrap: signs in to master and hardens it (REQ-0016)",
            secret=secret,
            service_account_enabled=True,
        )
        client = await master.get_client_by_client_id(plan.client_id)
        if client is None:
            raise PlatformDeclarationError(f"{plan.client_id}: created but not listed")
        uuid = client["id"]
        if await master.get_client_secret(uuid) != secret:
            raise PlatformDeclarationError(f"{plan.client_id}: created, but the secret did not take")
    else:
        assert plan.client is not None
        uuid = plan.client["id"]
        if plan.flags or plan.secret:
            rep = {**plan.client, **BOOTSTRAP_CLIENT_FLAGS}
            if plan.secret:
                rep["secret"] = secret
            await master.put_client(uuid, rep)
            if plan.secret and await master.get_client_secret(uuid) != secret:
                raise PlatformDeclarationError(f"{plan.client_id}: the configured secret did not take")

    if plan.roles:
        sa_user = await master.get_service_account_user(uuid)
        for role in plan.roles:
            await master.add_user_realm_role(sa_user["id"], role["name"])


# ---------------------------------------------------------------------------
# Hardening
# ---------------------------------------------------------------------------


def require_bootstrap_client(kc: KeycloakAdminClient, client_id: str) -> None:
    """Refuse unless `kc` is signed in as the bootstrap client, by this process, this run.

    `identity` is set only by `KeycloakAdminClient.authenticate_master_client` (which checks
    the token's `azp` and issuer) or copied by `adopt_session` from an instance that did.
    """
    identity = kc.identity
    if identity is None or identity.kind != MASTER_CLIENT or identity.name != client_id:
        who = f"{identity.kind} {identity.name}" if identity else "nobody"
        raise MasterHardeningRefused(
            f"hardening the master realm runs only with the bootstrap client {client_id}'s "
            f"own token, obtained and checked in this run; this session is {who}. An "
            f"administrator's own token could turn on the factor that cuts it off"
        )


@dataclass
class MasterHardeningPlan:
    """What hardening master would write, and the changes to report."""

    brute_force: bool
    mfa: bool
    settings: list[SettingChange] = field(default_factory=list)
    flow: AdminMfaPlan | None = None
    #: (user id, username) of master admins to get CONFIGURE_TOTP
    enrol: list[tuple[str, str]] = field(default_factory=list)

    @property
    def changes(self) -> list[SettingChange]:
        out = list(self.settings)
        if self.flow is not None:
            out.extend(self.flow.changes)
        out.extend(
            SettingChange(f"user {name}.requiredActions", None, [CONFIGURE_TOTP], MFA_SOURCE)
            for _, name in self.enrol
        )
        return out

    @property
    def destructive(self) -> list[SettingChange]:
        """Brute force turned off, or the second-factor flow unbound."""
        return [c for c in self.changes if destructive(c)]


def desired_master_settings(
    declaration: PlatformDeclaration, *, brute_force: bool
) -> tuple[dict[str, Any], dict[str, str]]:
    """`bruteForceProtected` and the declaration's brute-force tuning, for master."""
    desired = {k: declaration.realm_settings[k] for k in BRUTE_FORCE_TUNING if k in declaration.realm_settings}
    sources = {k: f"{declaration.sources.get(k, 'platform.yaml')} (master)" for k in desired}
    desired["bruteForceProtected"] = brute_force
    sources["bruteForceProtected"] = BRUTE_FORCE_SOURCE
    return desired, sources


def is_service_account(user: dict[str, Any]) -> bool:
    """A client's service account. `GET /roles/{role}/users` leaves out
    `serviceAccountClientLink` (measured on 26.7.3), so the reserved username prefix decides
    too: Keycloak names every service account `service-account-<clientId>` and refuses that
    prefix for a user created any other way."""
    return bool(user.get("serviceAccountClientLink")) or str(user.get("username", "")).startswith("service-account-")


async def plan_master_hardening(
    master: KeycloakAdminClient,
    declaration: PlatformDeclaration,
    *,
    brute_force: bool,
    mfa: bool,
) -> MasterHardeningPlan:
    """Read master and plan its hardening. Writes nothing; refuses before any write.

    Reading needs no particular token, so a dry run as the admin user can report it.
    """
    plan = MasterHardeningPlan(brute_force=brute_force, mfa=mfa)
    realm = await master.get_realm_settings()
    desired, sources = desired_master_settings(declaration, brute_force=brute_force)
    plan.settings = plan_realm_settings(desired, realm, sources)

    plan.flow = await plan_admin_mfa(
        master,
        required=mfa,
        role=MASTER_ADMIN_ROLE,
        retired_roles=(),
        browser_flow=realm.get("browserFlow"),
        organization=False,
        source=MFA_SOURCE,
    )

    if mfa:
        for user in await master.get_realm_role_users(MASTER_ADMIN_ROLE):
            if is_service_account(user):
                continue  # a client's service account (this one's own) never signs in by password
            if CONFIGURE_TOTP in (user.get("requiredActions") or []):
                continue
            credentials = await master.get_user_credentials(user["id"])
            if any(c.get("type") == "otp" for c in credentials):
                continue
            plan.enrol.append((user["id"], user.get("username", user["id"])))
    return plan


async def apply_master_hardening(
    master: KeycloakAdminClient, plan: MasterHardeningPlan, *, client_id: str
) -> None:
    """Write `plan`, as the bootstrap client only: settings, the flow, then the admins."""
    require_bootstrap_client(master, client_id)

    if plan.settings:
        await master.update_realm_settings({c.key: c.desired for c in plan.settings})
        after = await master.get_realm_settings()
        unstuck = [c.key for c in plan.settings if after.get(c.key) != c.desired]
        if unstuck:
            raise PlatformDeclarationError(
                f"master accepted the update but these keys did not take: {unstuck}"
            )
    if plan.flow is not None and plan.flow.changes:
        await apply_admin_mfa(master, plan.flow)
    for user_id, _ in plan.enrol:
        user = await master.get_user_by_id(user_id)
        if user is None:
            continue
        actions = list(user.get("requiredActions") or [])
        if CONFIGURE_TOTP not in actions:
            await master.put_user(user_id, {**user, "requiredActions": [*actions, CONFIGURE_TOTP]})


# ---------------------------------------------------------------------------
# Signing in
# ---------------------------------------------------------------------------


async def sign_in_to_master(master: KeycloakAdminClient, settings: "KeycloakSettings") -> bool:
    """Step 1: the bootstrap client if it is configured and works, else the admin user.

    Returns True when signed in as the client. Raises `KeycloakAuthError` when neither works.
    """
    secret = settings.bootstrap_secret
    reason = "CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_SECRET is not set"
    if secret:
        try:
            await master.authenticate_master_client(settings.bootstrap_client_id, secret)
            return True
        except KeycloakAuthError as e:
            reason = str(e)
    if not settings.has_admin_credentials:
        raise KeycloakAuthError(
            f"cannot sign in to master: the bootstrap client failed ({reason}) and no master "
            f"admin user is configured (CELINE_KEYCLOAK_ADMIN_USER / _PASSWORD) to create it"
        )
    await master.authenticate_admin_user()
    return False
