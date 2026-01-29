"""API request and response models."""

from typing import Any, Literal

from pydantic import BaseModel, Field

from .core import Action, Decision, FilterPredicate, Resource, ResourceType


# --- Generic Authorization ---


class AuthorizeRequest(BaseModel):
    """Generic authorization request.

    The JWT token should be passed in the Authorization header.
    """

    resource: Resource = Field(..., description="Resource being accessed")
    action: Action = Field(..., description="Action being performed")
    context: dict[str, Any] = Field(
        default_factory=dict, description="Additional context for policy evaluation"
    )


class AuthorizeResponse(BaseModel):
    """Generic authorization response."""

    allowed: bool
    reason: str = ""
    request_id: str


# --- Dataset-specific ---


class DatasetAccessLevel(str):
    """Dataset access levels."""

    OPEN = "open"
    INTERNAL = "internal"
    RESTRICTED = "restricted"


class DatasetAccessRequest(BaseModel):
    """Request to check dataset access."""

    dataset_id: str = Field(..., description="Dataset identifier")
    access_level: Literal["open", "internal", "restricted"] = Field(
        ..., description="Dataset access level"
    )
    action: Literal["read", "write", "admin"] = Field(default="read", description="Action type")


class DatasetAccessResponse(BaseModel):
    """Response for dataset access check."""

    allowed: bool
    reason: str = ""
    request_id: str


class DatasetFilterRequest(BaseModel):
    """Request to get row-level filters for a dataset."""

    dataset_id: str = Field(..., description="Dataset identifier")
    access_level: Literal["open", "internal", "restricted"] = Field(
        ..., description="Dataset access level"
    )


class DatasetFilterResponse(BaseModel):
    """Response with row-level filters."""

    allowed: bool
    filters: list[FilterPredicate] = Field(
        default_factory=list, description="Filters to apply to queries"
    )
    reason: str = ""
    request_id: str


# --- Pipeline-specific ---


class PipelineState(str):
    """Pipeline execution states."""

    PENDING = "pending"
    STARTED = "started"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PipelineTransitionRequest(BaseModel):
    """Request to validate a pipeline state transition."""

    pipeline_id: str = Field(..., description="Pipeline identifier")
    from_state: str = Field(..., description="Current state")
    to_state: str = Field(..., description="Target state")


class PipelineTransitionResponse(BaseModel):
    """Response for pipeline state transition."""

    allowed: bool
    reason: str = ""
    request_id: str


# --- Digital Twin-specific ---


class TwinAccessRequest(BaseModel):
    """Request to check digital twin access."""

    twin_id: str = Field(..., description="Twin identifier")
    action: Literal["read", "write", "simulate", "admin"] = Field(
        default="read", description="Action type"
    )


class TwinAccessResponse(BaseModel):
    """Response for twin access check."""

    allowed: bool
    reason: str = ""
    request_id: str


class TwinEventRequest(BaseModel):
    """Request to authorize a twin event emission."""

    twin_id: str = Field(..., description="Twin identifier")
    event_type: str = Field(..., description="Type of event")
    simulation_state: str | None = Field(None, description="Current simulation state")


class TwinEventResponse(BaseModel):
    """Response for twin event authorization."""

    allowed: bool
    reason: str = ""
    request_id: str


# --- MQTT-specific (mosquitto-go-auth compatible) ---


class MqttAuthRequest(BaseModel):
    """MQTT authentication request (mosquitto-go-auth format).

    Note: The actual JWT validation happens via the token in username field
    or Authorization header, depending on configuration.
    """

    username: str = Field(..., description="Username (may contain JWT)")
    password: str = Field(default="", description="Password (often empty for JWT auth)")
    clientid: str = Field(..., description="MQTT client ID")


class MqttAclRequest(BaseModel):
    """MQTT ACL check request (mosquitto-go-auth format)."""

    username: str = Field(..., description="Username")
    topic: str = Field(..., description="MQTT topic")
    clientid: str = Field(..., description="MQTT client ID")
    acc: Literal[1, 2, 3, 4] = Field(
        ...,
        description="Access type: 1=subscribe, 2=publish, 3=subscribe+publish, 4=subscribe literal",
    )


class MqttSuperuserRequest(BaseModel):
    """MQTT superuser check request."""

    username: str = Field(..., description="Username")


class MqttResponse(BaseModel):
    """MQTT auth/acl response.

    mosquitto-go-auth expects HTTP 200 for allow, 4xx for deny.
    We return a body for debugging purposes.
    """

    ok: bool
    reason: str = ""


# --- User Data Access ---


class UserDataAccessRequest(BaseModel):
    """Request to check user's access to their own data."""

    resource_type: str = Field(..., description="Type of user resource (dashboard, profile, etc.)")
    resource_id: str = Field(..., description="Resource identifier")
    owner_id: str = Field(..., description="Resource owner's user ID")
    action: Literal["read", "write", "delete", "share"] = Field(
        default="read", description="Action type"
    )


class UserDataAccessResponse(BaseModel):
    """Response for user data access check."""

    allowed: bool
    reason: str = ""
    request_id: str


# --- Health ---


class HealthResponse(BaseModel):
    """Health check response."""

    status: Literal["healthy", "unhealthy"]
    version: str
    policies_loaded: bool
    details: dict[str, Any] = Field(default_factory=dict)
