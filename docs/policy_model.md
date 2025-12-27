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
- **Human users** belong to one of the following groups:
  - `operators`
  - `managers`
  - `admins`

---

### restricted

Highly sensitive datasets.

Allowed if:
- **Service clients** have `dataset.admin`
- **Human users** belong to the `admins` group

---

## Access models

### Human users (group-based)

- Authenticate via interactive login
- Authorization based on group membership
- No OAuth scopes are evaluated for humans

Group hierarchy (implicit):

admins > managers > operators

---

### Service clients (scope-based)

- Authenticate using OAuth2 Client Credentials
- No group membership
- Capabilities expressed via OAuth scopes

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
