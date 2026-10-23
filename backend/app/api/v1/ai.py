from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_current_user, get_client_ip, get_user_agent
from app.models.user import User
from app.models.finding import Finding
from app.schemas.ai import AIExplanationResponse
from app.agents.llm_client import llm_client
from app.core.permissions import verify_tenant_isolation
from app.services.audit_service import AuditService

router = APIRouter()


@router.post("/findings/{finding_id}/explain", response_model=AIExplanationResponse)
def explain_finding_and_propose_remediation(
    finding_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Request specialized AI assistance to explain a finding's technical root cause,
    exploitability, and propose a minimal secure patch.
    Enforces secret redaction on all context prior to prompt construction.
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    verify_tenant_isolation(current_user, finding.project.tenant_id)

    # Get sanitized evidence snippet
    snippet = ""
    if finding.evidence:
        snippet = finding.evidence[0].sanitized_snippet

    explanation = llm_client.generate_remediation_explanation(
        finding_id=finding.id,
        title=finding.title,
        category=finding.category.value,
        cwe_id=finding.cwe_id,
        scanner_rule_id=finding.scanner_rule_id,
        sanitized_snippet=snippet
    )

    AuditService.log_event(
        db=db,
        tenant_id=current_user.tenant_id,
        actor=current_user,
        action="AI_EXPLANATION_REQUESTED",
        resource_type="FINDING",
        resource_id=finding.id,
        client_ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        details={"finding_id": finding.id, "rule": finding.scanner_rule_id}
    )

    return explanation
