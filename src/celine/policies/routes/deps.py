from typing import Annotated

from fastapi import Depends, Header, HTTPException

from celine.policies.auth.subject import extract_subject_from_claims
from celine.policies.main import (
    get_policy_engine as _get_policy_engine,
    get_jwt_validator as _get_jwt_validator,
    get_audit_logger as _get_audit_logger,
)
from celine.policies.models import Subject


def get_engine():
    return _get_policy_engine()


def get_jwt_validator():
    return _get_jwt_validator()


def get_audit_logger():
    return _get_audit_logger()


def get_subject(
    authorization: Annotated[str | None, Header()] = None,
    jwt_validator=Depends(get_jwt_validator),
) -> Subject:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    claims = jwt_validator.validate_authorization_header(authorization)
    return extract_subject_from_claims(claims)
