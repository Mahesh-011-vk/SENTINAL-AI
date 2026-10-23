from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict
from app.models.finding import FindingCategory, FindingSeverity, RiskLevel, FindingStatus


class FindingEvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    evidence_type: str
    file_path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    sanitized_snippet: str
    created_at: datetime


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    asset_id: str
    scan_job_id: str
    fingerprint: str
    title: str
    description: str
    category: FindingCategory
    scanner_name: str
    scanner_rule_id: str
    cwe_id: Optional[str] = None
    original_severity: FindingSeverity
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    internal_risk_level: RiskLevel
    internal_risk_score: float
    risk_rationale: Optional[str] = None
    status: FindingStatus
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    evidence: List[FindingEvidenceResponse] = []


class StatusTransitionRequest(BaseModel):
    new_status: FindingStatus
    rationale: str
