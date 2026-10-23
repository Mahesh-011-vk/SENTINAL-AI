from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict
from app.models.remediation import PatchReviewStatus


class RemediationCreate(BaseModel):
    finding_id: str
    assigned_to_id: str
    proposed_patch: Optional[str] = None
    remediation_notes: Optional[str] = None
    target_completion_date: Optional[datetime] = None


class PatchReviewRequest(BaseModel):
    patch_review_status: PatchReviewStatus
    review_notes: Optional[str] = None


class RemediationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    assigned_to_id: str
    proposed_patch: Optional[str] = None
    patch_review_status: PatchReviewStatus
    remediation_notes: Optional[str] = None
    target_completion_date: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
