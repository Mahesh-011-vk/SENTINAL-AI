from typing import List
from fastapi import HTTPException, status
from app.models.user import User, UserRole


ROLE_HIERARCHY = {
    UserRole.SUPERADMIN: [UserRole.SUPERADMIN, UserRole.SECURITY_ADMIN, UserRole.ENGINEER, UserRole.AUDITOR],
    UserRole.SECURITY_ADMIN: [UserRole.SECURITY_ADMIN, UserRole.ENGINEER, UserRole.AUDITOR],
    UserRole.ENGINEER: [UserRole.ENGINEER],
    UserRole.AUDITOR: [UserRole.AUDITOR],
}


def check_role(user: User, allowed_roles: List[UserRole]) -> bool:
    """Check if the user has one of the allowed roles or higher in the hierarchy."""
    user_roles = ROLE_HIERARCHY.get(user.role, [])
    return any(role in user_roles for role in allowed_roles)


def require_role_permission(user: User, allowed_roles: List[UserRole]) -> None:
    """Raise 403 Forbidden if user lacks sufficient role privileges."""
    if not check_role(user, allowed_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Operation requires one of the following roles: {[r.value for r in allowed_roles]}"
        )


def verify_tenant_isolation(user: User, resource_tenant_id: str) -> None:
    """Enforce strict multi-tenant boundary. Superadmins can cross-tenant if needed."""
    if user.role == UserRole.SUPERADMIN:
        return
    if user.tenant_id != resource_tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access prohibited"
        )
