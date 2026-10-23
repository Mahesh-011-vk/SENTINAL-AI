from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.models.audit import AuditLog
from app.models.user import User


class AuditService:
    @staticmethod
    def log_event(
        db: Session,
        tenant_id: str,
        action: str,
        resource_type: str,
        actor: Optional[User] = None,
        resource_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """Create and commit an immutable audit log record."""
        audit_entry = AuditLog(
            tenant_id=tenant_id,
            actor_id=actor.id if actor else None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            client_ip=client_ip,
            user_agent=user_agent,
            details_json=details or {},
        )
        db.add(audit_entry)
        db.commit()
        db.refresh(audit_entry)
        return audit_entry
