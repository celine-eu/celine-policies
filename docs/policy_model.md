# CELINE Dataset Policy Model

This document describes the authorization model implemented by the CELINE OPA policies.

The model is intentionally **simple**, **generic**, and **OIDC/OAuth-aligned**, so it can be reused across services and projects.

---

## Overview

Access decisions are based on **two independent dimensions**:

1. Dataset access level
2. Caller access model

---

## Dataset access levels

### open

- Publicly accessible
- No authentication required
- OPA allows access unconditionally

---

### internal

Moderately sensitive datasets.

Allowed if:
- **Service clients** have `dataset.query`
- **Human users** have role `manager` or `operator`

---

### restricted

Highly sensitive datasets.

Allowed if:
- **Service clients** have `dataset.admin`
- **Human users** have role `admin`

---

## Access models

### Human users (role-based)

- Interactive login
- Roles only (no scopes)
- Optional groups (unused by dataset policy)

Role hierarchy (implicit):

admin > manager > operator

---

### Service clients (scope-based)

- OAuth2 Client Credentials
- No groups
- No human roles
- Capabilities expressed via scopes

Supported scopes:

- dataset.query
- dataset.admin

---

## Subject inference

No explicit subject type is required.

- Presence of scopes → service client
- Absence of scopes → human user

---

## Anonymous access

If `subject` is null:
- Allowed only for `open` datasets
- Denied otherwise

---

## Design principles

- Fail closed
- Explicit privilege boundaries
- No project-specific identity concepts
- No service accounts in groups
- No custom token claims

---

## Rationale

This model mirrors common cloud IAM systems (AWS, Azure, GCP) while remaining simple, auditable, and extensible.
