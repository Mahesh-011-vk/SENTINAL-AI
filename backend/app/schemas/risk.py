from typing import Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from app.models.finding import FindingSeverity, RiskLevel
from app.models.asset import BusinessCriticality, AssetExposure


class RiskCalculationInput(BaseModel):
    severity: FindingSeverity
    asset_criticality: BusinessCriticality
    asset_exposure: AssetExposure
    exploitability_factor: float = Field(default=1.0, ge=0.5, le=2.0)
    confidence_factor: float = Field(default=1.0, ge=0.5, le=1.5)


class RiskExplanationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    calculated_score: float
    risk_level: RiskLevel
    engine_version: str
    rationale: str
    factor_breakdown: Dict[str, Any]
