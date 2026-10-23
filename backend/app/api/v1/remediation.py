from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_current_user, get_client_ip, get_user_agent
from app.models.user import User, UserRole
from app.models.finding import Finding, FindingStatus
from app.models.remediation import RemediationRecord, PatchReviewStatus
from app.schemas.remediation import RemediationCreate, RemediationResponse, PatchReviewRequest
from app.agents.verification_agent import verification_agent
from app.core.permissions import verify_tenant_isolation, require_role_permission
from app.services.audit_service import AuditService

router = APIRouter()


@router.post("/findings/{finding_id}/remediations", response_model=RemediationResponse, status_code=status.HTTP_201_CREATED)
def create_remediation(
    finding_id: str,
    payload: RemediationCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Assign an engineer to remediate a finding with an illustrative or proposed patch."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    verify_tenant_isolation(current_user, finding.project.tenant_id)

    # Transition finding to REMEDIATION_IN_PROGRESS
    finding.status = FindingStatus.REMEDIATION_IN_PROGRESS

    remediation = RemediationRecord(
        finding_id=finding.id,
        assigned_to_id=payload.assigned_to_id,
        proposed_patch=payload.proposed_patch,
        patch_review_status=PatchReviewStatus.PROPOSED,
        remediation_notes=payload.remediation_notes,
        target_completion_date=payload.target_completion_date
    )
    db.add(remediation)
    db.commit()
    db.refresh(remediation)

    AuditService.log_event(
        db=db,
        tenant_id=current_user.tenant_id,
        actor=current_user,
        action="REMEDIATION_ASSIGNED",
        resource_type="REMEDIATION_RECORD",
        resource_id=remediation.id,
        client_ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        details={"finding_id": finding.id, "assigned_to": payload.assigned_to_id}
    )

    return remediation


@router.patch("/remediations/{remediation_id}/review", response_model=RemediationResponse)
def review_proposed_patch(
    remediation_id: str,
    payload: PatchReviewRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Review a proposed remediation patch.
    Requires SECURITY_ADMIN or SUPERADMIN role.
    """
    require_role_permission(current_user, [UserRole.SECURITY_ADMIN, UserRole.SUPERADMIN])
    
    remediation = db.query(RemediationRecord).filter(RemediationRecord.id == remediation_id).first()
    if not remediation:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remediation record not found")
    verify_tenant_isolation(current_user, remediation.finding.project.tenant_id)

    remediation.patch_review_status = payload.patch_review_status
    if payload.review_notes:
        remediation.remediation_notes = (remediation.remediation_notes or "") + f"\nReview Notes: {payload.review_notes}"

    db.commit()
    db.refresh(remediation)

    AuditService.log_event(
        db=db,
        tenant_id=current_user.tenant_id,
        actor=current_user,
        action="PATCH_REVIEWED",
        resource_type="REMEDIATION_RECORD",
        resource_id=remediation.id,
        client_ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        details={"status": payload.patch_review_status.value}
    )

    return remediation


@router.post("/findings/{finding_id}/verify")
def verify_finding_fix(
    finding_id: str,
    verification_scan_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verify whether a previous finding has been resolved using evidence from a verification scan.
    Transitions finding to VERIFIED_RESOLVED or REOPENED.
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    verify_tenant_isolation(current_user, finding.project.tenant_id)

    record = verification_agent.verify_finding(
        db=db,
        finding_id=finding_id,
        verification_scan_id=verification_scan_id
    )

    AuditService.log_event(
        db=db,
        tenant_id=current_user.tenant_id,
        actor=current_user,
        action="FINDING_VERIFIED",
        resource_type="VERIFICATION_RECORD",
        resource_id=record.id,
        client_ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        details={"outcome": record.outcome.value, "finding_id": finding.id}
    )

    return {
        "finding_id": finding.id,
        "verification_record_id": record.id,
        "outcome": record.outcome.value,
        "comparison_notes": record.comparison_notes,
        "new_finding_status": finding.status.value,
        "verified_at": record.verified_at.isoformat()
    }
