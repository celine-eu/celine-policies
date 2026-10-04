"""An in-memory Keycloak for the authentication-flow, required-action and master-realm calls
`bootstrap` makes (REQ-0015, REQ-0016). Not a test module: `test_*` files import it.

It answers the way Keycloak 26.7.3 does where `admin_mfa.py` depends on it:

- `GET …/flows/{alias}/executions` works for a sub-flow's alias too, lists depth first with
  `level` counted from the flow asked for, names a sub-flow by `displayName` (its alias) and an
  authenticator by `providerId`;
- a new execution starts `DISABLED`;
- deleting the bound browser flow is refused (Keycloak answers 500);
- a config alias is unique in the realm (409).
"""

from __future__ import annotations

import itertools
from typing import Any

from celine.policies.cli.keycloak.client import (
    ADMIN_USER,
    MASTER_CLIENT,
    AuthIdentity,
    KeycloakConflictError,
    KeycloakError,
)

#: The authenticator ids Keycloak 26.7.3 lists that the flows here use.
PROVIDERS = {
    "auth-cookie", "auth-spnego", "identity-provider-redirector", "organization",
    "auth-username-password-form", "auth-otp-form", "auth-recovery-authn-code-form",
    "webauthn-authenticator", "conditional-user-configured", "conditional-user-role",
    "conditional-credential", "conditional-sub-flow-executed",
}

_ids = itertools.count(1)


def _id(prefix: str) -> str:
    return f"{prefix}-{next(_ids)}"


class FlowsFake:
    """Flows, configs, provider ids and required actions of one realm.

    Mix it into a fake realm that has `self.realm` (the representation) and `self.writes`.
    """

    def init_flows(self, *, organization: bool = True, providers: set[str] | None = None,
                   required_actions: dict[str, bool] | None = None) -> None:
        self.flows: dict[str, dict[str, Any]] = {}
        self.configs: dict[str, dict[str, Any]] = {}
        self.providers = set(PROVIDERS if providers is None else providers)
        self.required_actions = dict(
            {"CONFIGURE_TOTP": True, "CONFIGURE_RECOVERY_AUTHN_CODES": True}
            if required_actions is None else required_actions
        )
        self._keycloak_browser(organization)
        self.realm.setdefault("browserFlow", "browser")

    # --- building blocks, also used by tests to set a starting state ---

    def new_flow(self, alias: str, *, top: bool = True) -> dict[str, Any]:
        flow = {"id": _id("flow"), "alias": alias, "topLevel": top, "executions": []}
        self.flows[alias] = flow
        return flow

    def add(self, parent: str, provider: str | None = None, *, sub: str | None = None,
            requirement: str = "DISABLED", config: dict[str, str] | None = None,
            config_alias: str | None = None) -> dict[str, Any]:
        execution = {"id": _id("exec"), "requirement": requirement, "config": None}
        if sub is not None:
            self.new_flow(sub, top=False)
            execution["sub"] = sub
        else:
            execution["provider"] = provider
        if config is not None:
            config_id = _id("cfg")
            self.configs[config_id] = {"id": config_id, "alias": config_alias or provider, "config": dict(config)}
            execution["config"] = config_id
        self.flows[parent]["executions"].append(execution)
        return execution

    def _keycloak_browser(self, organization: bool) -> None:
        """Keycloak's own `browser` flow: as 26.7.3 has it in a new realm (and in master,
        without the organization step)."""
        self.new_flow("browser")
        self.add("browser", "auth-cookie", requirement="ALTERNATIVE")
        self.add("browser", "auth-spnego", requirement="DISABLED")
        self.add("browser", "identity-provider-redirector", requirement="ALTERNATIVE")
        if organization:
            self.add("browser", sub="Organization", requirement="ALTERNATIVE")
            self.add("Organization", sub="Browser - Conditional Organization", requirement="CONDITIONAL")
            self.add("Browser - Conditional Organization", "conditional-user-configured", requirement="REQUIRED")
            self.add("Browser - Conditional Organization", "organization", requirement="ALTERNATIVE")
        self.add("browser", sub="forms", requirement="ALTERNATIVE")
        self.add("forms", "auth-username-password-form", requirement="REQUIRED")
        self.add("forms", sub="Browser - Conditional 2FA", requirement="CONDITIONAL")
        self.add("Browser - Conditional 2FA", "conditional-user-configured", requirement="REQUIRED")
        self.add("Browser - Conditional 2FA", "auth-otp-form", requirement="ALTERNATIVE")

    def flow_shape(self, alias: str) -> list[tuple[int, str, str]]:
        return [
            (e["level"], e.get("displayName") if e.get("authenticationFlow") else e["providerId"], e["requirement"])
            for e in self._executions(alias)
        ]

    def config_of(self, alias: str, provider: str) -> dict[str, str]:
        """The config of the first execution of `provider` in flow `alias`, depth first."""
        for e in self._executions(alias):
            if e.get("providerId") == provider and e.get("authenticationConfig"):
                return self.configs[e["authenticationConfig"]]["config"]
        raise KeyError(provider)

    def _executions(self, alias: str, level: int = 0) -> list[dict[str, Any]]:
        out = []
        for e in self.flows[alias]["executions"]:
            rep: dict[str, Any] = {"id": e["id"], "level": level, "requirement": e["requirement"]}
            if "sub" in e:
                rep.update(authenticationFlow=True, displayName=e["sub"], flowId=self.flows[e["sub"]]["id"])
            else:
                rep.update(providerId=e["provider"], displayName=e["provider"])
            if e["config"]:
                rep["authenticationConfig"] = e["config"]
            out.append(rep)
            if "sub" in e:
                out.extend(self._executions(e["sub"], level + 1))
        return out

    def _find_execution(self, execution_id: str) -> dict[str, Any]:
        for flow in self.flows.values():
            for e in flow["executions"]:
                if e["id"] == execution_id:
                    return e
        raise KeycloakError(f"no execution {execution_id}", status_code=404)

    # --- the Admin API ---

    async def list_authentication_flows(self):
        return [{"id": f["id"], "alias": a, "topLevel": True} for a, f in self.flows.items() if f["topLevel"]]

    async def get_flow_executions(self, alias):
        if alias not in self.flows:
            raise KeycloakError(f"no flow {alias}", status_code=404)
        return self._executions(alias)

    async def get_authenticator_config(self, config_id):
        return dict(self.configs[config_id])

    async def update_authenticator_config(self, config_id, alias, config):
        self.writes.append(("config", alias))
        self.configs[config_id] = {"id": config_id, "alias": alias, "config": dict(config)}

    async def create_top_level_flow(self, alias, description):
        self.writes.append(("flow", alias))
        if alias in self.flows:
            raise KeycloakConflictError(alias, status_code=409)
        self.new_flow(alias)

    async def delete_authentication_flow(self, flow_id):
        alias = next(a for a, f in self.flows.items() if f["id"] == flow_id)
        if self.realm.get("browserFlow") == alias:
            raise KeycloakError("Unexpected response 500", status_code=500)
        self.writes.append(("delete-flow", alias))

        def drop(name):
            for e in self.flows.pop(name)["executions"]:
                if e["config"]:
                    self.configs.pop(e["config"], None)
                if "sub" in e:
                    drop(e["sub"])

        drop(alias)

    async def add_flow_authenticator(self, parent_alias, provider):
        self.writes.append(("execution", parent_alias, provider))
        self.add(parent_alias, provider)

    async def add_sub_flow(self, parent_alias, alias, description):
        self.writes.append(("sub-flow", parent_alias, alias))
        self.add(parent_alias, sub=alias)

    async def update_flow_execution(self, parent_alias, execution):
        self.writes.append(("requirement", execution["id"], execution["requirement"]))
        self._find_execution(execution["id"])["requirement"] = execution["requirement"]

    async def add_execution_config(self, execution_id, alias, config):
        if any(c["alias"] == alias for c in self.configs.values()):
            raise KeycloakConflictError(alias, status_code=409)
        self.writes.append(("add-config", alias))
        config_id = _id("cfg")
        self.configs[config_id] = {"id": config_id, "alias": alias, "config": dict(config)}
        self._find_execution(execution_id)["config"] = config_id

    async def list_authenticator_provider_ids(self):
        return set(self.providers)

    async def list_required_actions(self):
        return [{"alias": a, "enabled": on} for a, on in self.required_actions.items()]

    async def update_required_action(self, action):
        self.writes.append(("required-action", action["alias"]))
        self.required_actions[action["alias"]] = action["enabled"]


class MasterFake(FlowsFake):
    """The master realm: realm settings, flows, the admin users, and the clients and roles the
    bootstrap client is made of. One instance also plays the target realm's existence check."""

    def __init__(self, *, admins: dict[str, dict[str, Any]] | None = None,
                 client: dict[str, Any] | None = None, target_realms: tuple[str, ...] = ("celine",),
                 secret: str | None = None, realm: dict[str, Any] | None = None):
        self.realm = dict(realm or {"bruteForceProtected": False})
        self.writes: list[tuple] = []
        self.init_flows(organization=False)
        self.identity: AuthIdentity | None = None
        # username -> {"id", "requiredActions", "credentials": [types], "service": bool}
        self.users = {name: {"id": f"user-{name}", "requiredActions": [], "credentials": [], **u}
                      for name, u in (admins or {"admin": {}}).items()}
        self.realm_roles = {"admin", "create-realm", "default-roles-master"}
        role_names = ["view-realm", "manage-realm", "view-users", "manage-users", "view-clients",
                      "manage-clients", "query-groups", "query-users", "query-clients",
                      "view-organizations", "manage-organizations", "impersonation"]
        self.role_clients = {f"{r}-realm": {"id": f"uuid-{r}-realm", "roles": list(role_names)}
                             for r in ("master", *target_realms)}
        self.clients: dict[str, dict[str, Any]] = {}
        self.secrets: dict[str, str] = {}
        # service-account user id -> {"realm": set, "<client uuid>": set}
        self.sa_roles: dict[str, dict[str, set[str]]] = {}
        if client is not None:
            self._make_client(client.pop("clientId"), client, secret or "")

    def _make_client(self, client_id, rep, secret):
        uuid = f"uuid-{client_id}"
        self.clients[client_id] = {"id": uuid, "clientId": client_id, **rep}
        self.secrets[uuid] = secret
        self.sa_roles[f"sa-{uuid}"] = {"realm": set(rep.pop("_realm_roles", ()))}
        for container, names in rep.pop("_client_roles", {}).items():
            self.sa_roles[f"sa-{uuid}"][self.role_clients[container]["id"]] = set(names)
        return uuid

    # --- sign-in, as `KeycloakAdminClient` records it ---

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def authenticate_master_client(self, client_id, secret):
        from celine.policies.cli.keycloak.client import KeycloakAuthError

        client = self.clients.get(client_id)
        if client is None or self.secrets[client["id"]] != secret:
            raise KeycloakAuthError("invalid_client", status_code=401)
        self.writes_before_client = len(self.writes)
        self.identity = AuthIdentity(MASTER_CLIENT, client_id)

    async def authenticate_admin_user(self):
        self.identity = AuthIdentity(ADMIN_USER, "admin")

    def adopt_session(self, other):
        self.identity = other.identity

    async def authenticate(self):
        pass

    # --- realm ---

    async def get_realm_settings(self):
        return dict(self.realm)

    async def update_realm_settings(self, settings):
        self.writes.append(("master-realm", tuple(sorted(settings)), self.identity))
        self.realm.update(settings)

    # --- clients and roles ---

    async def get_client_by_client_id(self, client_id):
        if client_id in self.role_clients:
            return {"id": self.role_clients[client_id]["id"], "clientId": client_id}
        client = self.clients.get(client_id)
        return dict(client) if client else None

    async def get_client(self, uuid):
        return dict(next(c for c in self.clients.values() if c["id"] == uuid))

    async def get_client_secret(self, uuid):
        return self.secrets[uuid]

    async def create_client(self, *, client_id, name, description, secret, service_account_enabled):
        self.writes.append(("create-client", client_id, self.identity))
        rep = {"enabled": True, "publicClient": False, "bearerOnly": False,
               "serviceAccountsEnabled": service_account_enabled, "standardFlowEnabled": False,
               "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
               "clientAuthenticatorType": "client-secret"}
        uuid = self._make_client(client_id, rep, secret)
        return uuid, secret

    async def put_client(self, uuid, rep):
        self.writes.append(("put-client", rep["clientId"], self.identity))
        rep = dict(rep)
        secret = rep.pop("secret", None)
        if secret is not None:
            self.secrets[uuid] = secret
        self.clients[rep["clientId"]] = rep

    async def get_service_account_user(self, uuid):
        return {"id": f"sa-{uuid}"}

    async def get_user_realm_role_names(self, user_id):
        return set(self.sa_roles.get(user_id, {}).get("realm", set()))

    async def get_realm_role(self, name):
        return {"id": f"role-{name}", "name": name} if name in self.realm_roles else None

    async def add_user_realm_role(self, user_id, name):
        self.writes.append(("grant", user_id, name, self.identity))
        self.sa_roles.setdefault(user_id, {}).setdefault("realm", set()).add(name)

    async def get_client_roles(self, uuid):
        names = next(c["roles"] for c in self.role_clients.values() if c["id"] == uuid)
        return [{"id": f"{uuid}-{n}", "name": n} for n in names]

    async def get_user_client_roles(self, user_id, uuid):
        return [{"name": n} for n in self.sa_roles.get(user_id, {}).get(uuid, set())]

    async def assign_client_roles_to_user(self, user_id, uuid, roles):
        self.writes.append(("grant", user_id, uuid, tuple(sorted(r["name"] for r in roles)), self.identity))
        self.sa_roles.setdefault(user_id, {}).setdefault(uuid, set()).update(r["name"] for r in roles)

    # --- users ---

    async def get_realm_role_users(self, name):
        assert name == "admin"
        # As 26.7.3 lists them: no `serviceAccountClientLink`, the bootstrap client's own
        # service account among them once it holds `admin`.
        users = [
            {"id": u["id"], "username": n, "requiredActions": list(u["requiredActions"])}
            for n, u in self.users.items()
        ]
        for client_id, client in self.clients.items():
            if "admin" in self.sa_roles.get(f"sa-{client['id']}", {}).get("realm", set()):
                users.append({"id": f"sa-{client['id']}", "username": f"service-account-{client_id}",
                              "requiredActions": []})
        return users

    async def get_user_credentials(self, user_id):
        user = next(u for u in self.users.values() if u["id"] == user_id)
        return [{"type": t} for t in user["credentials"]]

    async def get_user_by_id(self, user_id):
        name, user = next((n, u) for n, u in self.users.items() if u["id"] == user_id)
        return {"id": user_id, "username": name, "requiredActions": list(user["requiredActions"])}

    async def put_user(self, user_id, rep):
        self.writes.append(("put-user", rep["username"], tuple(rep["requiredActions"]), self.identity))
        self.users[rep["username"]]["requiredActions"] = list(rep["requiredActions"])
