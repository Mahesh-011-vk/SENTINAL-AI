from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_current_user, get_client_ip, get_user_agent
from app.models.user import User, UserRole
from app.models.project import Project
from app.schemas.project import ProjectCreate, ProjectUpdate, ProjectResponse
from app.core.permissions import verify_tenant_isolation, require_role_permission
from app.services.audit_service import AuditService
from app.services.sbom_service import sbom_service
from app.services.policy_engine import policy_engine, PolicyConfig, PolicyEvaluationResult
from typing import Optional, Any, Dict

router = APIRouter()


@router.get("", response_model=List[ProjectResponse])
def list_projects(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all projects belonging to the user's tenant."""
    query = db.query(Project)
    if current_user.role != UserRole.SUPERADMIN:
        query = query.filter(Project.tenant_id == current_user.tenant_id)
    return query.order_by(Project.created_at.desc()).all()


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(
    payload: ProjectCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new security project within tenant boundary."""
    project = Project(
        tenant_id=current_user.tenant_id,
        name=payload.name,
        description=payload.description
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    AuditService.log_event(
        db=db,
        tenant_id=current_user.tenant_id,
        actor=current_user,
        action="PROJECT_CREATED",
        resource_type="PROJECT",
        resource_id=project.id,
        client_ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        details={"name": project.name}
    )

    return project


@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve project by ID, verifying tenant boundary."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    verify_tenant_isolation(current_user, project.tenant_id)
    return project


@router.put("/{project_id}", response_model=ProjectResponse)
def update_project(
    project_id: str,
    payload: ProjectUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update project details."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    verify_tenant_isolation(current_user, project.tenant_id)

    if payload.name is not None:
        project.name = payload.name
    if payload.description is not None:
        project.description = payload.description
    if payload.is_archived is not None:
        project.is_archived = payload.is_archived

    db.commit()
    db.refresh(project)

    AuditService.log_event(
        db=db,
        tenant_id=current_user.tenant_id,
        actor=current_user,
        action="PROJECT_UPDATED",
        resource_type="PROJECT",
        resource_id=project.id,
        client_ip=get_client_ip(request),
        user_agent=get_user_agent(request)
    )

    return project


@router.get("/{project_id}/sbom", response_model=Dict[str, Any])
def get_project_sbom(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Generate and return standard CycloneDX 1.5 JSON SBOM for project components and dependencies."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    verify_tenant_isolation(current_user, project.tenant_id)
    return sbom_service.generate_cyclonedx_sbom(db=db, project_id=project_id)


@router.post("/{project_id}/policy/evaluate", response_model=PolicyEvaluationResult)
def evaluate_project_policy(
    project_id: str,
    payload: Optional[PolicyConfig] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Evaluate project security posture against Policy-as-Code build gates.
    Returns pass/fail decision with observed vs threshold metrics and blocking finding IDs.
    """
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    verify_tenant_isolation(current_user, project.tenant_id)
    return policy_engine.evaluate(db=db, project_id=project_id, config=payload)
