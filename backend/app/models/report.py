import enum
from sqlalchemy import String, ForeignKey, Enum, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base, TimestampMixin, generate_uuid


class ReportType(str, enum.Enum):
    PDF = "PDF"
    JSON = "JSON"


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    generated_by_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    report_type: Mapped[ReportType] = mapped_column(Enum(ReportType), default=ReportType.JSON, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    file_path: Mapped[str] = mapped_column(String(1024), nullable=True)
    summary_metadata: Mapped[dict] = mapped_column(JSON, nullable=True)

    # Relationships
    project = relationship("Project", back_populates="reports")
    generated_by = relationship("User")
