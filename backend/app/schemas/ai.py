from typing import List, Optional
from pydantic import BaseModel


class AIExplanationRequest(BaseModel):
    finding_id: str
    include_patch_proposal: bool = True


class AIExplanationResponse(BaseModel):
    finding_id: str
    summary: str
    technical_root_cause: str
    exploitability_assessment: str
    remediation_guidance: str
    illustrative_patch_diff: Optional[str] = None
    suggested_unit_tests: List[str] = []
    authoritative_references: List[str] = []
    limitations_and_disclaimer: str = (
        "This AI-generated analysis is an untrusted advisory proposal grounded in sanitized scanner evidence. "
        "It must be reviewed and tested by a qualified security engineer prior to implementation."
    )
    is_unverified_proposal: bool = True
