import enum
from datetime import datetime, timezone
from sqlalchemy import String, ForeignKey, Enum, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base, TimestampMixin, generate_uuid


class VerificationOutcome(str, enum.Enum):
    VERIFIED_RESOLVED = "VERIFIED_RESOLVED"
    STILL_DETECTED = "STILL_DETECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class VerificationRecord(Base, TimestampMixin):
    __tablename__ = "verification_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    outcome: Mapped[VerificationOutcome] = mapped_column(Enum(VerificationOutcome), nullable=False)
    comparison_notes: Mapped[str] = mapped_column(Text, nullable=False)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    finding = relationship("Finding", back_populates="verifications")
    scan_job = relationship("ScanJob")
