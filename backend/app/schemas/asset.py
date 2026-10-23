from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict
from app.models.asset import AssetType, EnvironmentType, BusinessCriticality, AssetExposure


class AssetCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    asset_type: AssetType
    target_locator: str = Field(..., description="Repo URL, Web URL, Container Image reference")
    environment: EnvironmentType = EnvironmentType.DEVELOPMENT
    business_criticality: BusinessCriticality = BusinessCriticality.MEDIUM
    exposure: AssetExposure = AssetExposure.INTERNAL


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    environment: Optional[EnvironmentType] = None
    business_criticality: Optional[BusinessCriticality] = None
    exposure: Optional[AssetExposure] = None
    is_active: Optional[bool] = None


class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    name: str
    asset_type: AssetType
    target_locator: str
    environment: EnvironmentType
    business_criticality: BusinessCriticality
    exposure: AssetExposure
    is_active: bool
    created_at: datetime
    updated_at: datetime


class AssetAuthorizationCreate(BaseModel):
    scope_description: str = Field(..., min_length=10)
    allowed_domains: str = Field(..., description="Comma-separated allowed domains, e.g. api.example.com,app.example.com")
    allowed_ip_ranges: Optional[str] = None
    expires_at: datetime


class AssetAuthorizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_id: str
    authorized_by_id: str
    scope_description: str
    allowed_domains: str
    allowed_ip_ranges: Optional[str] = None
    expires_at: datetime
    is_revoked: bool
    created_at: datetime
