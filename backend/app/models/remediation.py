import enum
from datetime import datetime
from sqlalchemy import String, ForeignKey, Enum, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base, TimestampMixin, generate_uuid


class PatchReviewStatus(str, enum.Enum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"


class RemediationRecord(Base, TimestampMixin):
    __tablename__ = "remediation_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    assigned_to_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    proposed_patch: Mapped[str] = mapped_column(Text, nullable=True)  # Git unified diff or code snippet
    patch_review_status: Mapped[PatchReviewStatus] = mapped_column(Enum(PatchReviewStatus), default=PatchReviewStatus.PROPOSED, nullable=False)
    remediation_notes: Mapped[str] = mapped_column(Text, nullable=True)
    target_completion_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    finding = relationship("Finding", back_populates="remediations")
    assigned_to = relationship("User", back_populates="assigned_remediations")
