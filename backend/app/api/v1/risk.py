from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_current_user, get_client_ip, get_user_agent
from app.models.user import User, UserRole
from app.models.finding import Finding
from app.schemas.risk import RiskCalculationInput, RiskExplanationResponse
from app.services.risk_service import DeterministicRiskEngine
from app.services.audit_service import AuditService
from app.core.permissions import verify_tenant_isolation, require_role_permission

router = APIRouter()


@router.post("/calculate", response_model=RiskExplanationResponse)
def simulate_risk_calculation(
    payload: RiskCalculationInput,
    current_user: User = Depends(get_current_user)
):
    """
    Simulate transparent risk engine scoring without persisting.
    Exposes complete factor breakdown and documented formula rationale.
    """
    score, level, rationale, breakdown = DeterministicRiskEngine.calculate_risk(
        severity=payload.severity,
        asset_criticality=payload.asset_criticality,
        asset_exposure=payload.asset_exposure,
        exploitability_factor=payload.exploitability_factor,
        confidence_factor=payload.confidence_factor
    )

    return RiskExplanationResponse(
        finding_id="simulation",
        calculated_score=score,
        risk_level=level,
        engine_version=DeterministicRiskEngine.VERSION,
        rationale=rationale,
        factor_breakdown=breakdown
    )


@router.post("/findings/{finding_id}/recalculate", response_model=RiskExplanationResponse)
def recalculate_finding_risk(
    finding_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Recalculate internal risk score for an existing finding based on current asset metadata.
    Updates the database finding record and writes an audit event.
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    verify_tenant_isolation(current_user, finding.project.tenant_id)

    asset = finding.asset
    score, level, rationale, breakdown = DeterministicRiskEngine.calculate_risk(
        severity=finding.original_severity,
        asset_criticality=asset.business_criticality,
        asset_exposure=asset.exposure
    )

    finding.internal_risk_score = score
    finding.internal_risk_level = level
    finding.risk_rationale = rationale
    db.commit()
    db.refresh(finding)

    AuditService.log_event(
        db=db,
        tenant_id=current_user.tenant_id,
        actor=current_user,
        action="RISK_RECALCULATED",
        resource_type="FINDING",
        resource_id=finding.id,
        client_ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        details={"new_score": score, "new_level": level.value}
    )

    return RiskExplanationResponse(
        finding_id=finding.id,
        calculated_score=score,
        risk_level=level,
        engine_version=DeterministicRiskEngine.VERSION,
        rationale=rationale,
        factor_breakdown=breakdown
    )
