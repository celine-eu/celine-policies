# CELINE OPA Policies

Centralized Open Policy Agent (OPA) policies for the CELINE platform.

## Scope

This repository defines **authorization policies only**.
Authentication and coarse disclosure rules live in service code.

## Services using these policies

- Dataset API
- (future) Ingestion pipelines
- (future) Admin APIs

## Quick start

```bash
task opa:run
```

Test policy manually:



```bash
curl -X POST http://localhost:8181/v1/data/celine/dataset/access \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "dataset": {
        "disclosure_level": "internal"
      },
      "user": {
        "sub": "alice",
        "group_names": ["managers"]
      }
    }
  }'
```

```
curl -X POST http://localhost:8181/v1/data/celine/dataset/access \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "dataset": {
        "disclosure_level": "restricted",
        "governance": {
          "owner": "alice"
        }
      },
      "user": {
        "sub": "alice",
        "group_names": ["viewers"]
      }
    }
  }'
```

## Run tests

```bash
task test
```

## Format policies

```bash
task fmt
```

## Philosophy

- Policies are **pure logic**
- No service-specific hacks
- Strong test coverage
- Versioned and auditable
