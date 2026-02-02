# Getting Started

This guide walks you through integrating your service with the CELINE Policy Service.

## Prerequisites

- Access to the CELINE Keycloak instance
- An OAuth2 client configured for your service (see [Scopes & Permissions](scopes-and-permissions.md))
- Network access to the policy service endpoint

## Overview

Your service will:
1. Obtain a JWT from Keycloak (for users or service accounts)
2. Call the policy service with the JWT to check authorization
3. Proceed or deny based on the response

```
┌─────────────┐      ┌──────────────┐      ┌────────────────┐
│ Your Service│─────▶│Policy Service│─────▶│ Allow / Deny   │
│  + JWT      │      │              │      │ + Reason       │
└─────────────┘      └──────────────┘      └────────────────┘
```

## Step 1: Configure Your OAuth Client

Request a Keycloak client for your service with appropriate scopes. Example for a data processing service:

| Setting | Value |
|---------|-------|
| Client ID | `svc-my-service` |
| Client Type | Confidential |
| Service Account | Enabled |
| Scopes | `dataset.query`, `mqtt.write` |

## Step 2: Obtain a JWT

### For Service-to-Service (Client Credentials)

```python
import httpx

async def get_service_token() -> str:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://keycloak:8080/realms/celine/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "svc-my-service",
                "client_secret": "your-client-secret",
            }
        )
        return response.json()["access_token"]
```

### For User Requests

Pass through the user's JWT from the incoming request:

```python
from fastapi import Header

async def my_endpoint(authorization: str = Header(...)):
    # Forward this to policy service
    jwt_token = authorization  # "Bearer <token>"
```

## Step 3: Check Authorization

### Using the Generic `/authorize` Endpoint

```python
import httpx
from dataclasses import dataclass

@dataclass
class PolicyClient:
    base_url: str = "http://policy-service:8009"
    
    async def check_access(
        self,
        jwt_token: str,
        resource_type: str,
        resource_id: str,
        action: str,
        attributes: dict | None = None
    ) -> tuple[bool, str]:
        """
        Check if the request is authorized.
        
        Returns:
            (allowed, reason) tuple
        """
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/authorize",
                headers={
                    "Authorization": jwt_token,  # Include "Bearer " prefix
                    "X-Source-Service": "my-service",
                    "X-Request-Id": "correlation-id-here",
                },
                json={
                    "resource": {
                        "type": resource_type,
                        "id": resource_id,
                        "attributes": attributes or {},
                    },
                    "action": {
                        "name": action,
                    },
                },
            )
            data = response.json()
            return data["allowed"], data.get("reason", "")
```

### Example: Protecting a Dataset Endpoint

```python
from fastapi import FastAPI, Header, HTTPException

app = FastAPI()
policy = PolicyClient()

@app.get("/datasets/{dataset_id}")
async def get_dataset(
    dataset_id: str,
    authorization: str = Header(...),
):
    # Check authorization
    allowed, reason = await policy.check_access(
        jwt_token=authorization,
        resource_type="dataset",
        resource_id=dataset_id,
        action="read",
        attributes={"access_level": "internal"},
    )
    
    if not allowed:
        raise HTTPException(status_code=403, detail=reason)
    
    # Proceed with business logic
    return {"dataset_id": dataset_id, "data": "..."}
```

## Step 4: Use Domain-Specific Endpoints (Optional)

For common use cases, convenience endpoints are available:

### Dataset Access Check

```python
async def check_dataset_access(jwt: str, dataset_id: str, access_level: str, action: str = "read"):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{POLICY_URL}/dataset/access",
            headers={"Authorization": jwt},
            json={
                "dataset_id": dataset_id,
                "access_level": access_level,
                "action": action,
            },
        )
        return response.json()["allowed"]
```

### Dataset Row Filters

Get filters to apply to your database queries:

```python
async def get_dataset_filters(jwt: str, dataset_id: str, access_level: str):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{POLICY_URL}/dataset/filters",
            headers={"Authorization": jwt},
            json={
                "dataset_id": dataset_id,
                "access_level": access_level,
            },
        )
        data = response.json()
        if data["allowed"]:
            return data["filters"]  # Apply these to your query
        return None
```

### Pipeline State Transition

```python
async def can_transition_pipeline(jwt: str, pipeline_id: str, from_state: str, to_state: str):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{POLICY_URL}/pipeline/transition",
            headers={"Authorization": jwt},
            json={
                "pipeline_id": pipeline_id,
                "from_state": from_state,
                "to_state": to_state,
            },
        )
        return response.json()["allowed"]
```

## Step 5: Handle Responses

### Successful Authorization

```json
{
  "allowed": true,
  "reason": "user has viewer access and client has dataset.query scope",
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Denied Authorization

```json
{
  "allowed": false,
  "reason": "insufficient group privileges",
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

Map denial reasons to appropriate HTTP status codes:

| Reason Pattern | HTTP Status |
|----------------|-------------|
| "anonymous access denied" | 401 Unauthorized |
| "insufficient privileges" | 403 Forbidden |
| "missing scope" | 403 Forbidden |

## Complete Integration Example

```python
from fastapi import FastAPI, Header, HTTPException, Depends
from functools import lru_cache
import httpx

app = FastAPI()

class PolicyClient:
    def __init__(self, base_url: str = "http://policy-service:8009"):
        self.base_url = base_url
    
    async def authorize(
        self,
        jwt: str,
        resource_type: str,
        resource_id: str,
        action: str,
        attributes: dict | None = None,
        source_service: str = "my-service",
    ) -> dict:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                f"{self.base_url}/authorize",
                headers={
                    "Authorization": jwt,
                    "X-Source-Service": source_service,
                },
                json={
                    "resource": {
                        "type": resource_type,
                        "id": resource_id,
                        "attributes": attributes or {},
                    },
                    "action": {"name": action},
                },
            )
            response.raise_for_status()
            return response.json()

@lru_cache
def get_policy_client():
    return PolicyClient()

async def require_authorization(
    resource_type: str,
    resource_id: str,
    action: str,
    attributes: dict | None = None,
):
    """Dependency that enforces authorization."""
    async def checker(
        authorization: str = Header(...),
        policy: PolicyClient = Depends(get_policy_client),
    ):
        result = await policy.authorize(
            jwt=authorization,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            attributes=attributes,
        )
        if not result["allowed"]:
            raise HTTPException(
                status_code=403,
                detail=result.get("reason", "Access denied"),
            )
        return result
    return checker

# Usage
@app.get("/twin/{twin_id}")
async def get_twin(
    twin_id: str,
    auth_result: dict = Depends(
        require_authorization(
            resource_type="dt",
            resource_id="twin_id",  # Will be resolved
            action="read",
        )
    ),
):
    return {"twin_id": twin_id, "status": "ok"}
```

## Testing Your Integration

### Local Testing with Docker Compose

```bash
# Start the stack
docker compose up -d

# Get a test token (adjust for your Keycloak setup)
TOKEN=$(curl -s -X POST \
  "http://localhost:8080/realms/celine/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=svc-test" \
  -d "client_secret=test-secret" \
  | jq -r '.access_token')

# Test authorization
curl -X POST http://localhost:8009/authorize \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "resource": {"type": "dataset", "id": "test", "attributes": {"access_level": "internal"}},
    "action": {"name": "read"}
  }'
```

### Unit Testing with Mocks

```python
import pytest
from unittest.mock import AsyncMock, patch

@pytest.fixture
def mock_policy_client():
    with patch("myapp.policy.PolicyClient") as mock:
        client = mock.return_value
        client.authorize = AsyncMock(return_value={
            "allowed": True,
            "reason": "test",
            "request_id": "test-123",
        })
        yield client

async def test_authorized_access(mock_policy_client):
    # Your test using the mocked policy client
    result = await mock_policy_client.authorize(...)
    assert result["allowed"] is True
```

## Next Steps

- Review [Scopes & Permissions](scopes-and-permissions.md) to understand what scopes your service needs
- See [API Reference](api-reference.md) for complete endpoint documentation
- Check [MQTT Integration](mqtt-integration.md) if your service uses MQTT
