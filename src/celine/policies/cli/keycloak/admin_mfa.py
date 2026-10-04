"""The platform admin's second factor: the realm's browser flow, as `bootstrap` converges it.

REQ-0015, ADR-0013. The flow reached a realm only through infra's realm import, which Keycloak
skips for a realm that already exists, and its condition named the realm role `admin` that
`bootstrap` now deletes (ADR-0012). So `bootstrap` owns it: on every run, from any starting
realm, it converges the flow below and binds it, or binds Keycloak's own `browser` when the
second factor is off (dev, unless `CELINE_KEYCLOAK_ADMIN_MFA_REQUIRED` says otherwise).

## The shape (measured on Keycloak 26.7.3)

The plan `participants-may-choose-a-passkey-or-a-one-time-code`, Phase 1, validated it on a
throwaway realm, and infra's import carried the same flow:

    browser-admin-second-factor
      Cookie                                              ALTERNATIVE
      Kerberos                                            DISABLED
      Identity Provider Redirector                        ALTERNATIVE
      … organization                                      ALTERNATIVE   (as Keycloak's own)
        … conditional organization                        CONDITIONAL
          Condition - user configured                     REQUIRED
          Organization Identity-First Login               ALTERNATIVE
      … forms                                             ALTERNATIVE
        Username Password Form (offers the passkey)       REQUIRED
        … admin                                           CONDITIONAL
          Condition - user role: platform-admin           REQUIRED
          Condition - credential: no webauthn-passwordless REQUIRED
          … configured                                    CONDITIONAL
            Condition - user configured                   REQUIRED
            OTP Form | Recovery Authentication Code Form  ALTERNATIVE
          … enrol                                         CONDITIONAL
            Condition - sub-flow executed: configured, not-executed  REQUIRED
            OTP Form, Recovery Authentication Code Form   REQUIRED

The traps it avoids (store knowledge `an-admin-second-factor-flow-can-lock-out-everyone`):

- an unknown provider id is accepted by Keycloak and then fails **every** browser sign-in, so
  every id below is checked against the server before any write;
- a conditional sub-flow of only ALTERNATIVE factors refuses an admin who has none as
  "invalid username or password", hence the `enrol` branch;
- `Condition - user configured` is true when any alternative is configured, so a recovery
  removes the TOTP and the recovery codes together.

## Converging

- **No flow by that name:** built, then bound.
- **A flow of another shape** (a step, a requirement or an order differs): deleted and rebuilt.
  Keycloak refuses (500) to delete the bound browser flow, so the realm is bound to its own
  `browser` for the length of the rebuild.
- **The same shape, a condition's value differs** (the role `admin` an older import named):
  corrected in place.
- **A `Condition - user role` on a retired role in any other flow** is repointed to
  `platform-admin`, whether the second factor is on or off: the retired role is deleted, and a
  condition on it would silently match nobody.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from celine.policies.cli.keycloak.platform import PlatformDeclarationError, SettingChange

if TYPE_CHECKING:
    from celine.policies.cli.keycloak.client import KeycloakAdminClient

#: The flow `bootstrap` owns. The same alias infra's import used, so a realm imported with it
#: converges in place.
ADMIN_MFA_FLOW = "browser-admin-second-factor"
#: Keycloak's own browser flow, bound when the second factor is off.
KEYCLOAK_BROWSER_FLOW = "browser"
#: Where every change below comes from, in a report.
ADMIN_MFA_SOURCE = "CELINE_KEYCLOAK_ADMIN_MFA_REQUIRED"
#: The required actions the `enrol` branch starts. Keycloak 26.7.3 registers and enables both
#: in a new realm; `bootstrap` enables them when disabled and refuses when unregistered.
REQUIRED_ACTIONS = ("CONFIGURE_TOTP", "CONFIGURE_RECOVERY_AUTHN_CODES")
#: The condition whose role is checked against the retired roles in every flow.
ROLE_CONDITION = "conditional-user-role"

FLOW_DESCRIPTION = (
    "Password or passkey for everyone; platform admins who did not use a passkey also need "
    "TOTP or a recovery code (celine-policies keycloak bootstrap)"
)


@dataclass(frozen=True)
class Node:
    """One execution of the declared flow: an authenticator, or a sub-flow with children."""

    name: str  # the provider id, or the sub-flow's alias
    requirement: str
    children: tuple["Node", ...] | None = None
    description: str = ""
    config_alias: str | None = None
    config: tuple[tuple[str, str], ...] = ()

    @property
    def is_flow(self) -> bool:
        return self.children is not None


def _auth(provider: str, requirement: str, config_alias: str | None = None, **config: str) -> Node:
    return Node(provider, requirement, None, "", config_alias, tuple(config.items()))


def _sub(suffix: str, requirement: str, description: str, *children: Node) -> Node:
    return Node(f"{ADMIN_MFA_FLOW} {suffix}", requirement, tuple(children), description)


def desired_flow(role: str, *, organization: bool = True) -> tuple[Node, ...]:
    """The flow's executions under its top level, for the admin role `role`.

    `organization=False` leaves out the organization step, for the master realm (REQ-0016):
    Keycloak's own browser flow there has none, and master has no organizations.
    """
    configured = f"{ADMIN_MFA_FLOW} configured"
    org_step = (
        _sub(
            "organization", "ALTERNATIVE", "As in Keycloak's own browser flow",
            _sub(
                "conditional organization", "CONDITIONAL",
                "Organization identity-first login, for users who belong to one",
                _auth("conditional-user-configured", "REQUIRED"),
                _auth("organization", "ALTERNATIVE"),
            ),
        ),
    ) if organization else ()
    return (
        _auth("auth-cookie", "ALTERNATIVE"),
        _auth("auth-spnego", "DISABLED"),
        _auth("identity-provider-redirector", "ALTERNATIVE"),
        *org_step,
        _sub(
            "forms", "ALTERNATIVE", "Username and password, or a passkey from the same page",
            _auth("auth-username-password-form", "REQUIRED"),
            _sub(
                "admin", "CONDITIONAL", "Admins who did not sign in with a passkey",
                _auth("conditional-user-role", "REQUIRED", f"{ADMIN_MFA_FLOW}-admin-role",
                      condUserRole=role, negate="false"),
                _auth("conditional-credential", "REQUIRED", f"{ADMIN_MFA_FLOW}-no-passkey",
                      credentials="webauthn-passwordless", included="false"),
                _sub(
                    "configured", "CONDITIONAL", "An admin who has a second factor uses it",
                    _auth("conditional-user-configured", "REQUIRED"),
                    _auth("auth-otp-form", "ALTERNATIVE"),
                    _auth("auth-recovery-authn-code-form", "ALTERNATIVE"),
                ),
                _sub(
                    "enrol", "CONDITIONAL",
                    "An admin who has none enrols TOTP and recovery codes. Without this branch "
                    "Keycloak refuses them as 'invalid username or password'",
                    _auth("conditional-sub-flow-executed", "REQUIRED", f"{ADMIN_MFA_FLOW}-not-configured",
                          flow_to_check=configured, check_result="not-executed"),
                    _auth("auth-otp-form", "REQUIRED"),
                    _auth("auth-recovery-authn-code-form", "REQUIRED"),
                ),
            ),
        ),
    )


@dataclass(frozen=True)
class Step:
    """What the shape compares of one execution, in the depth-first order Keycloak lists them."""

    level: int
    is_flow: bool
    name: str
    requirement: str
    configured: bool


def flatten(nodes: Sequence[Node], level: int = 0) -> list[tuple[Step, Node]]:
    out: list[tuple[Step, Node]] = []
    for node in nodes:
        out.append((Step(level, node.is_flow, node.name, node.requirement, bool(node.config)), node))
        if node.children:
            out.extend(flatten(node.children, level + 1))
    return out


def provider_ids(nodes: Sequence[Node]) -> set[str]:
    """Every authenticator provider id the flow names."""
    return {node.name for _, node in flatten(nodes) if not node.is_flow}


@dataclass
class CurrentStep:
    step: Step
    execution: dict[str, Any]
    config_id: str | None = None
    config_alias: str | None = None
    config: dict[str, str] = field(default_factory=dict)


async def read_flow(
    kc: "KeycloakAdminClient", alias: str, *, configs_of: set[str] | None = None
) -> list[CurrentStep]:
    """A flow as Keycloak lists it, with the configs of the executions whose provider is in
    `configs_of` (every configured execution when None)."""
    steps: list[CurrentStep] = []
    for execution in await kc.get_flow_executions(alias):
        is_flow = bool(execution.get("authenticationFlow"))
        name = execution.get("displayName") if is_flow else execution.get("providerId")
        config_id = execution.get("authenticationConfig")
        current = CurrentStep(
            Step(int(execution.get("level", 0)), is_flow, name or "", execution.get("requirement", ""),
                 bool(config_id)),
            execution,
            config_id,
        )
        if config_id and (configs_of is None or name in configs_of):
            config = await kc.get_authenticator_config(config_id)
            current.config_alias = config.get("alias")
            current.config = dict(config.get("config") or {})
        steps.append(current)
    return steps


@dataclass
class AdminMfaPlan:
    """What converging the second factor would write, and the changes to report."""

    required: bool
    role: str = ""
    organization: bool = True
    changes: list[SettingChange] = field(default_factory=list)
    #: required-action representations to write back with `enabled: true`
    required_actions: list[dict[str, Any]] = field(default_factory=list)
    #: the id of a flow of another shape under ADMIN_MFA_FLOW, deleted before the build
    rebuild_flow_id: str | None = None
    create_flow: bool = False
    #: (config id, alias, config) to write in place
    config_updates: list[tuple[str, str, dict[str, str]]] = field(default_factory=list)
    #: the flow to bind as the browser flow, when the realm binds another
    bind: str | None = None


async def plan_admin_mfa(
    kc: "KeycloakAdminClient",
    *,
    required: bool,
    role: str,
    retired_roles: Sequence[str],
    browser_flow: str | None,
    organization: bool = True,
    source: str = ADMIN_MFA_SOURCE,
) -> AdminMfaPlan:
    """Read the realm's flows and plan the convergence. Writes nothing; refuses before any write.

    `browser_flow` is the realm's `browserFlow` as read. `organization` and `source` as for
    the master realm (REQ-0016): no organization step, and the report names the master.
    """
    plan = AdminMfaPlan(required=required, role=role, organization=organization)
    flows = {f.get("alias"): f for f in await kc.list_authentication_flows()}
    shape = desired_flow(role, organization=organization)
    desired = flatten(shape)

    if required:
        missing = sorted(provider_ids(shape) - await kc.list_authenticator_provider_ids())
        if missing:
            raise PlatformDeclarationError(
                f"the admin second factor needs the authenticators {missing}, which this Keycloak "
                f"does not list. A flow naming them would fail every browser sign-in; set "
                f"{ADMIN_MFA_SOURCE}=false or deploy a Keycloak that has them"
            )
        actions = {a.get("alias"): a for a in await kc.list_required_actions()}
        unregistered = [alias for alias in REQUIRED_ACTIONS if alias not in actions]
        if unregistered:
            raise PlatformDeclarationError(
                f"the admin second factor enrols through the required actions {unregistered}, "
                f"which this realm has not registered"
            )
        for alias in REQUIRED_ACTIONS:
            if not actions[alias].get("enabled"):
                plan.required_actions.append({**actions[alias], "enabled": True})
                plan.changes.append(SettingChange(f"requiredAction {alias}.enabled", False, True, source))

        if ADMIN_MFA_FLOW not in flows:
            plan.create_flow = True
            plan.changes.append(SettingChange(f"authenticationFlow {ADMIN_MFA_FLOW}", None, "created", source))
        else:
            current = await read_flow(kc, ADMIN_MFA_FLOW)
            if [c.step for c in current] != [step for step, _ in desired]:
                plan.rebuild_flow_id = flows[ADMIN_MFA_FLOW]["id"]
                plan.create_flow = True
                plan.changes.append(SettingChange(
                    f"authenticationFlow {ADMIN_MFA_FLOW}", "another shape", "rebuilt", source
                ))
            else:
                for cur, (_, node) in zip(current, desired):
                    _plan_config(plan, cur, dict(node.config), source)

    # A condition on a retired role, anywhere else: repointed whether the factor is on or off.
    retired = set(retired_roles)
    for alias in flows:
        if required and alias == ADMIN_MFA_FLOW:
            continue  # converged above
        for cur in await read_flow(kc, alias, configs_of={ROLE_CONDITION}):
            if cur.step.name == ROLE_CONDITION and cur.config.get("condUserRole") in retired:
                _plan_config(plan, cur, {"condUserRole": role}, source)

    bound = ADMIN_MFA_FLOW if required else KEYCLOAK_BROWSER_FLOW
    if browser_flow != bound:
        plan.bind = bound
        plan.changes.append(SettingChange("browserFlow", browser_flow, bound, source))
    return plan


def _plan_config(plan: AdminMfaPlan, cur: CurrentStep, want: dict[str, str], source: str) -> None:
    differs = {k: v for k, v in want.items() if cur.config.get(k) != v}
    if not differs or cur.config_id is None:
        return
    plan.config_updates.append((cur.config_id, cur.config_alias or "", {**cur.config, **want}))
    for key, value in differs.items():
        plan.changes.append(SettingChange(
            f"authenticatorConfig {cur.config_alias or cur.config_id}.{key}",
            cur.config.get(key), value, source,
        ))


def _last(executions: list[dict[str, Any]], node: Node) -> dict[str, Any]:
    """The execution just added under a parent: its level-0 entries, the last matching one."""
    matching = [
        e for e in executions
        if e.get("level", 0) == 0
        and (e.get("displayName") == node.name if node.is_flow else e.get("providerId") == node.name)
    ]
    if not matching:
        raise PlatformDeclarationError(f"{node.name}: added to the flow but not listed by Keycloak")
    return matching[-1]


async def _build(kc: "KeycloakAdminClient", parent: str, nodes: Sequence[Node]) -> None:
    for node in nodes:
        if node.is_flow:
            await kc.add_sub_flow(parent, node.name, node.description)
        else:
            await kc.add_flow_authenticator(parent, node.name)
        execution = _last(await kc.get_flow_executions(parent), node)
        if execution.get("requirement") != node.requirement:
            await kc.update_flow_execution(parent, {**execution, "requirement": node.requirement})
        if node.config:
            await kc.add_execution_config(execution["id"], node.config_alias or node.name, dict(node.config))
        if node.children:
            await _build(kc, node.name, node.children)


async def apply_admin_mfa(kc: "KeycloakAdminClient", plan: AdminMfaPlan) -> None:
    """Write `plan`: required actions, the flow, the configs, then the binding, in that order,
    so a flow is never bound before it is complete."""
    for action in plan.required_actions:
        await kc.update_required_action(action)

    if plan.rebuild_flow_id is not None:
        if (await kc.get_realm_settings()).get("browserFlow") == ADMIN_MFA_FLOW:
            await kc.update_realm_settings({"browserFlow": KEYCLOAK_BROWSER_FLOW})
        await kc.delete_authentication_flow(plan.rebuild_flow_id)
    if plan.create_flow:
        await kc.create_top_level_flow(ADMIN_MFA_FLOW, FLOW_DESCRIPTION)
        await _build(kc, ADMIN_MFA_FLOW, desired_flow(plan.role, organization=plan.organization))

    for config_id, alias, config in plan.config_updates:
        await kc.update_authenticator_config(config_id, alias, config)

    bound = ADMIN_MFA_FLOW if plan.required else KEYCLOAK_BROWSER_FLOW
    if (await kc.get_realm_settings()).get("browserFlow") != bound:
        await kc.update_realm_settings({"browserFlow": bound})
