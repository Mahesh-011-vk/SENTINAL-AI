from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict
from app.models.scan import ScanType, ScanStatus, ScannerName, ScannerExecutionStatus


class ScanJobCreate(BaseModel):
    asset_id: str
    scan_type: ScanType = ScanType.FULL


class ScannerExecutionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scanner_name: ScannerName
    scanner_version: str
    status: ScannerExecutionStatus
    exit_code: int
    execution_time_seconds: float
    error_log: Optional[str] = None
    created_at: datetime


class ScanJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    asset_id: str
    triggered_by_id: str
    scan_type: ScanType
    status: ScanStatus
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    executions: List[ScannerExecutionResponse] = []
