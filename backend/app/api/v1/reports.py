from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_current_user, get_client_ip, get_user_agent
from app.models.user import User
from app.models.project import Project
from app.models.report import Report, ReportType
from app.schemas.report import ReportGenerateRequest, ReportResponse
from app.agents.reporting_agent import reporting_agent
from app.core.permissions import verify_tenant_isolation
from app.services.audit_service import AuditService

router = APIRouter()


@router.post("/projects/{project_id}/reports", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
def generate_report(
    project_id: str,
    payload: ReportGenerateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Generate an authorized compliance security report (PDF or JSON)."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    verify_tenant_isolation(current_user, project.tenant_id)

    report_title = payload.title or f"{project.name} Security Assessment Report"
    summary_data = reporting_agent.generate_json_report(db, project_id)

    report = Report(
        project_id=project_id,
        generated_by_id=current_user.id,
        report_type=payload.report_type,
        title=report_title,
        summary_metadata=summary_data["summary_metrics"]
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    AuditService.log_event(
        db=db,
        tenant_id=current_user.tenant_id,
        actor=current_user,
        action="REPORT_GENERATED",
        resource_type="REPORT",
        resource_id=report.id,
        client_ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        details={"report_type": report.report_type.value, "project_id": project_id}
    )

    return report


@router.get("/reports/{report_id}/download")
def download_report(
    report_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Download generated PDF binary or JSON report."""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    verify_tenant_isolation(current_user, report.project.tenant_id)

    if report.report_type == ReportType.PDF:
        pdf_bytes = reporting_agent.generate_pdf_report(db, report.project_id)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="sentinelai-report-{report.id[:8]}.pdf"'}
        )
    else:
        json_data = reporting_agent.generate_json_report(db, report.project_id)
        return json_data
