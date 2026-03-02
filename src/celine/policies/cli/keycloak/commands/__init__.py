"""Keycloak management CLI.

Provides commands to sync scopes, clients, and scope assignments to Keycloak.
"""

from celine.policies.cli.keycloak.settings import KeycloakSettings
from celine.policies.cli.keycloak.models import KeycloakConfig, ScopeConfig, ClientConfig
from celine.policies.cli.keycloak.client import KeycloakAdminClient
from celine.policies.cli.keycloak.sync import compute_sync_plan, apply_sync_plan, SyncPlan

__all__ = [
    "KeycloakSettings",
    "KeycloakConfig",
    "ScopeConfig",
    "ClientConfig",
    "KeycloakAdminClient",
    "compute_sync_plan",
    "apply_sync_plan",
    "SyncPlan",
]
