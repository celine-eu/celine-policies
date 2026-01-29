"""Core domain models for policy evaluation."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SubjectType(str, Enum):
    """Type of subject making the request."""

    USER = "user"
    SERVICE = "service"
    ANONYMOUS = "anonymous"


class Subject(BaseModel):
    """Represents the authenticated principal.

    For users: identified by groups (from Keycloak group membership)
    For services: identified by scopes (from Keycloak client scopes)
    """

    id: str = Field(..., description="Subject identifier (sub claim or client_id)")
    type: SubjectType = Field(..., description="User, service, or anonymous")
    groups: list[str] = Field(default_factory=list, description="Group memberships (users)")
    scopes: list[str] = Field(default_factory=list, description="OAuth scopes (services)")
    claims: dict[str, Any] = Field(
        default_factory=dict, description="Raw JWT claims for policy flexibility"
    )

    @classmethod
    def anonymous(cls) -> "Subject":
        """Create an anonymous subject."""
        return cls(id="anonymous", type=SubjectType.ANONYMOUS)


class ResourceType(str, Enum):
    """Types of resources that can be authorized."""

    DATASET = "dataset"
    PIPELINE = "pipeline"
    TWIN = "twin"
    TOPIC = "topic"
    USERDATA = "userdata"


class Resource(BaseModel):
    """Represents the resource being accessed."""

    type: ResourceType = Field(..., description="Resource type")
    id: str = Field(..., description="Resource identifier")
    attributes: dict[str, Any] = Field(
        default_factory=dict, description="Resource-specific attributes"
    )


class Action(BaseModel):
    """Represents the action being performed."""

    name: str = Field(..., description="Action name (read, write, subscribe, etc.)")
    context: dict[str, Any] = Field(
        default_factory=dict, description="Action-specific context (e.g., state transitions)"
    )


class PolicyInput(BaseModel):
    """Complete input for policy evaluation."""

    subject: Subject | None = Field(None, description="Authenticated subject (null for anonymous)")
    resource: Resource = Field(..., description="Resource being accessed")
    action: Action = Field(..., description="Action being performed")
    environment: dict[str, Any] = Field(
        default_factory=dict, description="Environmental context (timestamp, request_id, etc.)"
    )


class FilterPredicate(BaseModel):
    """A filter predicate for row-level access control."""

    field: str = Field(..., description="Field to filter on")
    operator: str = Field(..., description="Comparison operator (eq, ne, in, gt, lt, etc.)")
    value: Any = Field(..., description="Value to compare against")


class Decision(BaseModel):
    """Policy decision result."""

    allowed: bool = Field(..., description="Whether the action is allowed")
    reason: str = Field(default="", description="Human-readable explanation")
    policy: str = Field(default="", description="Policy path that made the decision")
    filters: list[FilterPredicate] = Field(
        default_factory=list, description="Row-level filters to apply (dataset policies)"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional metadata from policy evaluation"
    )


class AuditRecord(BaseModel):
    """Audit log entry for policy decisions."""

    timestamp: datetime = Field(default_factory=datetime.utcnow)
    request_id: str = Field(..., description="Unique request identifier")
    decision: Decision = Field(..., description="Policy decision")
    input: PolicyInput = Field(..., description="Policy input")
    latency_ms: float = Field(..., description="Evaluation latency in milliseconds")
    cached: bool = Field(default=False, description="Whether result was from cache")
    source_service: str | None = Field(None, description="Calling service identifier")
