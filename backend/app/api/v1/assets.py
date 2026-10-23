from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_current_user, get_client_ip, get_user_agent
from app.models.user import User, UserRole
from app.models.project import Project
from app.models.asset import Asset, AssetAuthorization
from app.schemas.asset import (
    AssetCreate,
    AssetResponse,
    AssetAuthorizationCreate,
    AssetAuthorizationResponse,
)
from app.core.permissions import verify_tenant_isolation, require_role_permission
from app.services.audit_service import AuditService

router = APIRouter()


@router.get("/projects/{project_id}/assets", response_model=List[AssetResponse])
def list_project_assets(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all assets registered within a project."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    verify_tenant_isolation(current_user, project.tenant_id)

    return db.query(Asset).filter(Asset.project_id == project_id).all()


@router.post("/projects/{project_id}/assets", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def register_asset(
    project_id: str,
    payload: AssetCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Register an authorized asset (Repository, Web App, Container, API) to a project."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    verify_tenant_isolation(current_user, project.tenant_id)

    asset = Asset(
        project_id=project_id,
        name=payload.name,
        asset_type=payload.asset_type,
        target_locator=payload.target_locator.strip(),
        environment=payload.environment,
        business_criticality=payload.business_criticality,
        exposure=payload.exposure,
        is_active=True
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)

    AuditService.log_event(
        db=db,
        tenant_id=current_user.tenant_id,
        actor=current_user,
        action="ASSET_REGISTERED",
        resource_type="ASSET",
        resource_id=asset.id,
        client_ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        details={"name": asset.name, "type": asset.asset_type.value, "locator": asset.target_locator}
    )

    return asset


@router.get("/assets/{asset_id}", response_model=AssetResponse)
def get_asset(
    asset_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve asset details."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    verify_tenant_isolation(current_user, asset.project.tenant_id)
    return asset


@router.post("/assets/{asset_id}/authorizations", response_model=AssetAuthorizationResponse, status_code=status.HTTP_201_CREATED)
def create_asset_authorization(
    asset_id: str,
    payload: AssetAuthorizationCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Issue a signed authorization record for web or active assessments.
    Mandatory prior to triggering any DAST assessment.
    Requires SECURITY_ADMIN or SUPERADMIN role.
    """
    require_role_permission(current_user, [UserRole.SECURITY_ADMIN, UserRole.SUPERADMIN])
    
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    verify_tenant_isolation(current_user, asset.project.tenant_id)

    auth_record = AssetAuthorization(
        asset_id=asset_id,
        authorized_by_id=current_user.id,
        scope_description=payload.scope_description,
        allowed_domains=payload.allowed_domains,
        allowed_ip_ranges=payload.allowed_ip_ranges,
        expires_at=payload.expires_at,
        is_revoked=False
    )
    db.add(auth_record)
    db.commit()
    db.refresh(auth_record)

    AuditService.log_event(
        db=db,
        tenant_id=current_user.tenant_id,
        actor=current_user,
        action="ASSET_AUTHORIZED",
        resource_type="ASSET_AUTHORIZATION",
        resource_id=auth_record.id,
        client_ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        details={"asset_id": asset_id, "allowed_domains": payload.allowed_domains}
    )

    return auth_record


@router.get("/assets/{asset_id}/authorizations", response_model=List[AssetAuthorizationResponse])
def list_asset_authorizations(
    asset_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List authorization records for an asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    verify_tenant_isolation(current_user, asset.project.tenant_id)

    return db.query(AssetAuthorization).filter(AssetAuthorization.asset_id == asset_id).all()
