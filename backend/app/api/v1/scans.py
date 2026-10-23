from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_current_user, get_client_ip, get_user_agent
from app.models.user import User, UserRole
from app.models.project import Project
from app.models.asset import Asset, AssetType, AssetAuthorization
from app.models.scan import ScanJob, ScanType, ScanStatus, ScannerExecution
from app.schemas.scan import ScanJobCreate, ScanJobResponse
from app.core.permissions import verify_tenant_isolation, require_role_permission
from app.services.audit_service import AuditService

router = APIRouter()


@router.post("/projects/{project_id}/scans", response_model=ScanJobResponse, status_code=status.HTTP_202_ACCEPTED)
def trigger_scan(
    project_id: str,
    payload: ScanJobCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Trigger an asynchronous security assessment job.
    Enforces authorization check for web/DAST scans.
    """
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    verify_tenant_isolation(current_user, project.tenant_id)

    asset = db.query(Asset).filter(Asset.id == payload.asset_id, Asset.project_id == project_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target asset not found in project")

    # Enforce mandatory AssetAuthorization for DAST / Web scans
    if payload.scan_type in (ScanType.DAST, ScanType.FULL) and asset.asset_type in (AssetType.WEB_APPLICATION, AssetType.API_ENDPOINT):
        now = datetime.now(timezone.utc)
        valid_auth = db.query(AssetAuthorization).filter(
            AssetAuthorization.asset_id == asset.id,
            AssetAuthorization.is_revoked == False,
            AssetAuthorization.expires_at > now
        ).first()

        if not valid_auth:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Web application assessment requires a valid, unexpired AssetAuthorizationRecord signed by a Security Admin"
            )

    # Create scan job
    job = ScanJob(
        project_id=project_id,
        asset_id=asset.id,
        triggered_by_id=current_user.id,
        scan_type=payload.scan_type,
        status=ScanStatus.PENDING,
        started_at=datetime.now(timezone.utc)
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    AuditService.log_event(
        db=db,
        tenant_id=current_user.tenant_id,
        actor=current_user,
        action="SCAN_TRIGGERED",
        resource_type="SCAN_JOB",
        resource_id=job.id,
        client_ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        details={"scan_type": job.scan_type.value, "asset_id": asset.id}
    )

    return job


@router.get("/scans/{scan_id}", response_model=ScanJobResponse)
def get_scan_status(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve scan status and per-scanner execution records."""
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")
    verify_tenant_isolation(current_user, job.project.tenant_id)
    return job


@router.post("/scans/{scan_id}/cancel", response_model=ScanJobResponse)
def cancel_scan(
    scan_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cancel a pending or running assessment job."""
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")
    verify_tenant_isolation(current_user, job.project.tenant_id)

    if job.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot cancel scan in status {job.status.value}")

    job.status = ScanStatus.CANCELLED
    job.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(job)

    AuditService.log_event(
        db=db,
        tenant_id=current_user.tenant_id,
        actor=current_user,
        action="SCAN_CANCELLED",
        resource_type="SCAN_JOB",
        resource_id=job.id,
        client_ip=get_client_ip(request),
        user_agent=get_user_agent(request)
    )

    return job
