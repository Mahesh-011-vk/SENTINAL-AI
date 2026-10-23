from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, ConfigDict
from app.models.report import ReportType


class ReportGenerateRequest(BaseModel):
    project_id: str
    report_type: ReportType = ReportType.JSON
    title: Optional[str] = None


class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    generated_by_id: str
    report_type: ReportType
    title: str
    file_path: Optional[str] = None
    summary_metadata: Optional[Dict[str, Any]] = None
    created_at: datetime
