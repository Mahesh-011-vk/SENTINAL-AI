import enum
from sqlalchemy import String, Boolean, ForeignKey, Enum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base, TimestampMixin, generate_uuid


class UserRole(str, enum.Enum):
    SUPERADMIN = "SUPERADMIN"
    SECURITY_ADMIN = "SECURITY_ADMIN"
    ENGINEER = "ENGINEER"
    AUDITOR = "AUDITOR"


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole),
        default=UserRole.ENGINEER,
        nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    tenant = relationship("Tenant", back_populates="users")
    created_scans = relationship("ScanJob", back_populates="triggered_by", foreign_keys="ScanJob.triggered_by_id")
    audit_logs = relationship("AuditLog", back_populates="actor", foreign_keys="AuditLog.actor_id")
    assigned_remediations = relationship("RemediationRecord", back_populates="assigned_to", foreign_keys="RemediationRecord.assigned_to_id")
