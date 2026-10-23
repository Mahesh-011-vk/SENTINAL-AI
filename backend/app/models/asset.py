import enum
from datetime import datetime
from sqlalchemy import String, Boolean, ForeignKey, Text, Enum, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base, TimestampMixin, generate_uuid


class AssetType(str, enum.Enum):
    REPOSITORY = "REPOSITORY"
    WEB_APPLICATION = "WEB_APPLICATION"
    CONTAINER_IMAGE = "CONTAINER_IMAGE"
    API_ENDPOINT = "API_ENDPOINT"


class EnvironmentType(str, enum.Enum):
    PRODUCTION = "PRODUCTION"
    STAGING = "STAGING"
    DEVELOPMENT = "DEVELOPMENT"


class BusinessCriticality(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AssetExposure(str, enum.Enum):
    INTERNET_FACING = "INTERNET_FACING"
    INTERNAL = "INTERNAL"
    RESTRICTED = "RESTRICTED"


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    asset_type: Mapped[AssetType] = mapped_column(Enum(AssetType), nullable=False)
    target_locator: Mapped[str] = mapped_column(String(1024), nullable=False)  # repo URL, Web URL, container ref
    environment: Mapped[EnvironmentType] = mapped_column(Enum(EnvironmentType), default=EnvironmentType.DEVELOPMENT, nullable=False)
    business_criticality: Mapped[BusinessCriticality] = mapped_column(Enum(BusinessCriticality), default=BusinessCriticality.MEDIUM, nullable=False)
    exposure: Mapped[AssetExposure] = mapped_column(Enum(AssetExposure), default=AssetExposure.INTERNAL, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    project = relationship("Project", back_populates="assets")
    authorizations = relationship("AssetAuthorization", back_populates="asset", cascade="all, delete-orphan")
    scan_jobs = relationship("ScanJob", back_populates="asset", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")


class AssetAuthorization(Base, TimestampMixin):
    """Formal authorization record mandatory for web/DAST assessments."""
    __tablename__ = "asset_authorizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    authorized_by_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    scope_description: Mapped[str] = mapped_column(Text, nullable=False)
    allowed_domains: Mapped[str] = mapped_column(String(1024), nullable=False)  # Comma-separated or JSON
    allowed_ip_ranges: Mapped[str] = mapped_column(String(1024), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    asset = relationship("Asset", back_populates="authorizations")
    authorized_by = relationship("User")
