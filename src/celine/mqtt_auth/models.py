"""Request and response models for MQTT auth endpoints."""

from pydantic import BaseModel, Field


class MqttAuthRequest(BaseModel):
    """MQTT user authentication request from mosquitto-go-auth."""

    username: str = Field(..., description="MQTT username")
    password: str = Field(..., description="MQTT password")
    clientid: str = Field(..., description="MQTT client ID")


class MqttAclRequest(BaseModel):
    """MQTT ACL check request from mosquitto-go-auth."""

    clientid: str = Field(..., description="MQTT client ID")
    topic: str = Field(..., description="MQTT topic")
    acc: int = Field(
        ..., description="Access type bitmask (1=read, 2=publish, 4=subscribe)"
    )


class MqttSuperuserRequest(BaseModel):
    """MQTT superuser check request from mosquitto-go-auth."""

    username: str = Field(..., description="MQTT username")


class MqttResponse(BaseModel):
    """Response for MQTT auth/acl/superuser endpoints."""

    ok: bool = Field(..., description="Whether the action is allowed")
    reason: str = Field(default="", description="Human-readable reason")
