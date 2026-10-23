import enum
from datetime import datetime
from sqlalchemy import String, ForeignKey, Enum, DateTime, Text, Float, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base, TimestampMixin, generate_uuid


class FindingCategory(str, enum.Enum):
    SAST = "SAST"
    SCA = "SCA"
    SECRET = "SECRET"
    DAST = "DAST"
    CONFIG = "CONFIG"


class FindingSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskLevel(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    REMEDIATION_IN_PROGRESS = "REMEDIATION_IN_PROGRESS"
    RESOLVED_VERIFICATION_PENDING = "RESOLVED_VERIFICATION_PENDING"
    VERIFIED_RESOLVED = "VERIFIED_RESOLVED"
    REOPENED = "REOPENED"


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Deduplication fingerprint: sha256(category + rule_id + file_path + line_or_package)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[FindingCategory] = mapped_column(Enum(FindingCategory), nullable=False, index=True)
    scanner_name: Mapped[str] = mapped_column(String(100), nullable=False)
    scanner_rule_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    cwe_id: Mapped[str] = mapped_column(String(50), nullable=True, index=True)
    
    # Scanner-reported severity vs internal risk engine score
    original_severity: Mapped[FindingSeverity] = mapped_column(Enum(FindingSeverity), nullable=False)
    cvss_score: Mapped[float] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str] = mapped_column(String(100), nullable=True)
    
    # Internal deterministic risk prioritization
    internal_risk_level: Mapped[RiskLevel] = mapped_column(Enum(RiskLevel), default=RiskLevel.MEDIUM, nullable=False)
    internal_risk_score: Mapped[float] = mapped_column(Float, default=50.0, nullable=False)
    risk_rationale: Mapped[str] = mapped_column(Text, nullable=True)
    
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.OPEN, nullable=False, index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    
    duplicate_group_id: Mapped[str] = mapped_column(String(36), ForeignKey("duplicate_groups.id"), nullable=True)

    # Relationships
    project = relationship("Project", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")
    scan_job = relationship("ScanJob", back_populates="findings")
    evidence = relationship("FindingEvidence", back_populates="finding", cascade="all, delete-orphan")
    duplicate_group = relationship("DuplicateGroup", back_populates="findings")
    status_history = relationship("FindingStatusHistory", back_populates="finding", cascade="all, delete-orphan")
    remediations = relationship("RemediationRecord", back_populates="finding", cascade="all, delete-orphan")
    verifications = relationship("VerificationRecord", back_populates="finding", cascade="all, delete-orphan")


class FindingEvidence(Base, TimestampMixin):
    """Sanitized evidence substantiating a finding."""
    __tablename__ = "finding_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False)  # CODE_SNIPPET, HTTP_TRACE, DEPENDENCY_PATH, SECRET_HASH
    file_path: Mapped[str] = mapped_column(String(1024), nullable=True)
    start_line: Mapped[int] = mapped_column(Integer, nullable=True)
    end_line: Mapped[int] = mapped_column(Integer, nullable=True)
    sanitized_snippet: Mapped[str] = mapped_column(Text, nullable=False)
    raw_hash: Mapped[str] = mapped_column(String(64), nullable=True)

    # Relationships
    finding = relationship("Finding", back_populates="evidence")


class DuplicateGroup(Base, TimestampMixin):
    """Group tracking recurring or duplicated findings across scan cycles."""
    __tablename__ = "duplicate_groups"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    canonical_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    first_detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Relationships
    findings = relationship("Finding", back_populates="duplicate_group")


class FindingStatusHistory(Base, TimestampMixin):
    """Audit record for finding triage and state changes."""
    __tablename__ = "finding_status_history"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    previous_status: Mapped[str] = mapped_column(String(50), nullable=False)
    new_status: Mapped[str] = mapped_column(String(50), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)

    # Relationships
    finding = relationship("Finding", back_populates="status_history")
    user = relationship("User")
