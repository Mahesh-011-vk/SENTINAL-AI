from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_current_user
from app.models.user import User, UserRole
from app.models.audit import AuditLog
from app.schemas.audit import AuditLogResponse
from app.core.permissions import require_role_permission

router = APIRouter()


@router.get("", response_model=List[AuditLogResponse])
def list_audit_logs(
    action: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List tenant audit logs.
    Restricted to SECURITY_ADMIN, AUDITOR, or SUPERADMIN roles.
    """
    require_role_permission(current_user, [UserRole.SECURITY_ADMIN, UserRole.AUDITOR, UserRole.SUPERADMIN])

    query = db.query(AuditLog)
    if current_user.role != UserRole.SUPERADMIN:
        query = query.filter(AuditLog.tenant_id == current_user.tenant_id)

    if action:
        query = query.filter(AuditLog.action == action)

    return query.order_by(AuditLog.created_at.desc()).limit(limit).all()
