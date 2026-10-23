from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_current_user, get_client_ip, get_user_agent
from app.models.user import User, UserRole
from app.models.project import Project
from app.models.finding import (
    Finding,
    FindingCategory,
    FindingSeverity,
    RiskLevel,
    FindingStatus,
    FindingStatusHistory
)
from app.schemas.finding import FindingResponse, StatusTransitionRequest
from app.core.permissions import verify_tenant_isolation
from app.services.audit_service import AuditService

router = APIRouter()


@router.get("/projects/{project_id}/findings", response_model=List[FindingResponse])
def list_findings(
    project_id: str,
    status_filter: Optional[FindingStatus] = Query(None, alias="status"),
    category: Optional[FindingCategory] = None,
    risk_level: Optional[RiskLevel] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List normalized findings for a project with optional filters."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    verify_tenant_isolation(current_user, project.tenant_id)

    query = db.query(Finding).filter(Finding.project_id == project_id)
    if status_filter:
        query = query.filter(Finding.status == status_filter)
    if category:
        query = query.filter(Finding.category == category)
    if risk_level:
        query = query.filter(Finding.internal_risk_level == risk_level)

    return query.order_by(Finding.internal_risk_score.desc()).all()


@router.get("/findings/{finding_id}", response_model=FindingResponse)
def get_finding_detail(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve full finding details including sanitized evidence."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    verify_tenant_isolation(current_user, finding.project.tenant_id)
    return finding


@router.patch("/findings/{finding_id}/status", response_model=FindingResponse)
def update_finding_status(
    finding_id: str,
    payload: StatusTransitionRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Transition finding workflow status with mandatory justification.
    Records transition in FindingStatusHistory and audit log.
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    verify_tenant_isolation(current_user, finding.project.tenant_id)

    previous_status = finding.status.value
    finding.status = payload.new_status

    # Record in history table
    history_entry = FindingStatusHistory(
        finding_id=finding.id,
        user_id=current_user.id,
        previous_status=previous_status,
        new_status=payload.new_status.value,
        rationale=payload.rationale
    )
    db.add(history_entry)
    db.commit()
    db.refresh(finding)

    AuditService.log_event(
        db=db,
        tenant_id=current_user.tenant_id,
        actor=current_user,
        action="FINDING_STATUS_CHANGED",
        resource_type="FINDING",
        resource_id=finding.id,
        client_ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        details={"previous": previous_status, "new": payload.new_status.value, "rationale": payload.rationale}
    )

    return finding
