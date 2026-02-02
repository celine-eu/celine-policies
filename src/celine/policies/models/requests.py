"""API request and response models."""

from typing import Any, Literal

from pydantic import BaseModel, Field

from .core import Action, FilterPredicate, Resource


class AuthorizeRequest(BaseModel):
    """Generic authorization request.

    The JWT token should be passed in the Authorization header.
    """

    resource: Resource = Field(..., description="Resource being accessed")
    action: Action = Field(..., description="Action being performed")
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context for policy evaluation",
        json_schema_extra={"title": "AuthorizeRequestContext"},
    )


class AuthorizeResponse(BaseModel):
    """Generic authorization response."""

    allowed: bool
    reason: str = ""
    request_id: str


class DatasetAccessRequest(BaseModel):
    """Request to check dataset access."""

    dataset_id: str = Field(..., description="Dataset identifier")
    access_level: Literal["open", "internal", "restricted"] = Field(
        ..., description="Dataset access level"
    )
    action: Literal["read", "write", "admin"] = Field(
        default="read", description="Action type"
    )


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


class DtAccessRequest(BaseModel):
    """Request to check digital twin (dt) access."""

    dt_id: str = Field(..., description="DT identifier")
    action: Literal["read", "write", "simulate", "admin"] = Field(
        default="read", description="Action type"
    )


class DtAccessResponse(BaseModel):
    """Response for dt access check."""

    allowed: bool
    reason: str = ""
    request_id: str


class DtEventRequest(BaseModel):
    """Request to authorize a dt event emission."""

    dt_id: str = Field(..., description="DT identifier")
    event_type: str = Field(..., description="Type of event")
    simulation_state: str | None = Field(None, description="Current simulation state")


class DtEventResponse(BaseModel):
    """Response for dt event authorization."""

    allowed: bool
    reason: str = ""
    request_id: str


class MqttAuthRequest(BaseModel):
    """MQTT authentication request (mosquitto-go-auth format)."""

    username: str = Field(..., description="Username (may contain JWT)")
    password: str = Field(default="", description="Password (often empty for JWT auth)")
    clientid: str = Field(default="", description="MQTT client ID")


class MqttAclRequest(BaseModel):
    """MQTT ACL check request (mosquitto-go-auth format).

    mosquitto ACL checks use a bitmask:
    - MOSQ_ACL_READ      0x01
    - MOSQ_ACL_WRITE     0x02
    - MOSQ_ACL_SUBSCRIBE 0x04
    """

    username: str = Field(..., description="Username")
    topic: str = Field(..., description="MQTT topic")
    clientid: str = Field(default="", description="MQTT client ID")
    acc: int = Field(..., ge=0, le=7, description="Access mask (READ|WRITE|SUBSCRIBE)")


class MqttSuperuserRequest(BaseModel):
    """MQTT superuser check request."""

    username: str = Field(..., description="Username")


class MqttResponse(BaseModel):
    """MQTT auth/acl response."""

    ok: bool
    reason: str = ""


class UserDataAccessRequest(BaseModel):
    """Request to check user's access to their own data."""

    resource_type: str = Field(
        ..., description="Type of user resource (dashboard, profile, etc.)"
    )
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


class HealthResponse(BaseModel):
    """Health check response."""

    status: Literal["healthy", "unhealthy"]
    version: str
    policies_loaded: bool
    details: dict[str, Any] = Field(default_factory=dict)
