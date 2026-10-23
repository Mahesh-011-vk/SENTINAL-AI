import enum
from datetime import datetime
from sqlalchemy import String, ForeignKey, Enum, DateTime, Integer, Text, Float
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base, TimestampMixin, generate_uuid


class ScanType(str, enum.Enum):
    FULL = "FULL"
    SAST = "SAST"
    SCA = "SCA"
    SECRET = "SECRET"
    DAST = "DAST"
    CONFIG = "CONFIG"


class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScannerName(str, enum.Enum):
    SEMGREP = "SEMGREP"
    OSV_SCANNER = "OSV_SCANNER"
    GITLEAKS = "GITLEAKS"
    OWASP_ZAP = "OWASP_ZAP"
    CONFIG_AUDIT = "CONFIG_AUDIT"
    MOCK_SCANNER = "MOCK_SCANNER"


class ScannerExecutionStatus(str, enum.Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    SKIPPED = "SKIPPED"


class ScanJob(Base, TimestampMixin):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    triggered_by_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType), default=ScanType.FULL, nullable=False)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    project = relationship("Project", back_populates="scan_jobs")
    asset = relationship("Asset", back_populates="scan_jobs")
    triggered_by = relationship("User", back_populates="created_scans")
    executions = relationship("ScannerExecution", back_populates="scan_job", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan_job", cascade="all, delete-orphan")


class ScannerExecution(Base, TimestampMixin):
    """Detailed record for each distinct scanner invoked in a scan job."""
    __tablename__ = "scanner_executions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    scan_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    scanner_name: Mapped[ScannerName] = mapped_column(Enum(ScannerName), nullable=False)
    scanner_version: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[ScannerExecutionStatus] = mapped_column(Enum(ScannerExecutionStatus), default=ScannerExecutionStatus.SUCCESS, nullable=False)
    exit_code: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    execution_time_seconds: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    error_log: Mapped[str] = mapped_column(Text, nullable=True)

    # Relationships
    scan_job = relationship("ScanJob", back_populates="executions")
