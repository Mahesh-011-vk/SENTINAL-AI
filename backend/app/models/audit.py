from sqlalchemy import String, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base, TimestampMixin, generate_uuid


class AuditLog(Base, TimestampMixin):
    """Immutable audit trail for all security-relevant platform operations."""
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)  # e.g. AUTH_LOGIN, SCAN_TRIGGERED, RISK_RECALCULATED
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)     # e.g. SCAN_JOB, ASSET, FINDING
    resource_id: Mapped[str] = mapped_column(String(100), nullable=True)
    client_ip: Mapped[str] = mapped_column(String(50), nullable=True)
    user_agent: Mapped[str] = mapped_column(String(255), nullable=True)
    details_json: Mapped[dict] = mapped_column(JSON, nullable=True)

    # Relationships
    tenant = relationship("Tenant", back_populates="audit_logs")
    actor = relationship("User", back_populates="audit_logs")
