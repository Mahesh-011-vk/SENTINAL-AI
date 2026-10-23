import enum
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.models.finding import Finding, FindingCategory, FindingSeverity, FindingStatus
from app.models.asset import Asset, AssetExposure


class PolicyStatus(str, enum.Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    WARNING = "WARNING"


class PolicyConfig(BaseModel):
    max_critical_findings: int = Field(0, description="Maximum permitted active critical findings (default: 0)")
    max_high_findings: int = Field(2, description="Maximum permitted active high findings (default: 2)")
    max_risk_score: float = Field(60.0, description="Maximum overall risk score (0.0 - 100.0)")
    allow_unresolved_secrets: bool = Field(False, description="Whether open secret leaks are permitted")
    max_cvss_threshold: float = Field(8.5, description="Maximum CVSS score permitted without mitigation")
    enforce_production_tls: bool = Field(True, description="Require TLS enforcement on public assets")


class PolicyRuleResult(BaseModel):
    rule_id: str
    title: str
    status: str  # "PASS" | "FAIL" | "WARN"
    severity: str
    threshold: Any
    observed_value: Any
    message: str


class PolicyEvaluationResult(BaseModel):
    project_id: str
    overall_status: PolicyStatus
    summary: str
    evaluated_at: str
    engine_version: str
    total_active_findings: int
    blocking_findings_count: int
    rule_results: List[PolicyRuleResult]
    blocking_finding_ids: List[str]


class PolicyEngine:
    """
    Deterministic Policy-as-Code Engine v1.0.0.
    Evaluates project security findings, asset exposures, and risk scores
    against CI/CD build gate policies.
    """

    ENGINE_VERSION = "1.0.0"

    @classmethod
    def evaluate(
        cls,
        db: Session,
        project_id: str,
        config: Optional[PolicyConfig] = None
    ) -> PolicyEvaluationResult:
        if config is None:
            config = PolicyConfig()

        active_statuses = [
            FindingStatus.OPEN,
            FindingStatus.TRIAGED,
            FindingStatus.REMEDIATION_IN_PROGRESS,
            FindingStatus.REOPENED,
        ]

        active_findings: List[Finding] = db.query(Finding).filter(
            Finding.project_id == project_id,
            Finding.status.in_(active_statuses)
        ).all()

        assets: List[Asset] = db.query(Asset).filter(Asset.project_id == project_id).all()

        critical_count = sum(1 for f in active_findings if f.original_severity == FindingSeverity.CRITICAL)
        high_count = sum(1 for f in active_findings if f.original_severity == FindingSeverity.HIGH)
        secret_findings = [f for f in active_findings if f.category == FindingCategory.SECRET]
        high_cvss_findings = [f for f in active_findings if (f.cvss_score or 0.0) >= config.max_cvss_threshold]

        # Calculate project aggregate risk score
        risk_scores = [f.internal_risk_score for f in active_findings if f.internal_risk_score is not None]
        avg_risk_score = round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0.0

        rule_results: List[PolicyRuleResult] = []
        blocking_ids: set[str] = set()

        # Rule 1: Max Critical Findings
        r1_pass = critical_count <= config.max_critical_findings
        if not r1_pass:
            for f in active_findings:
                if f.original_severity == FindingSeverity.CRITICAL:
                    blocking_ids.add(f.id)
        rule_results.append(PolicyRuleResult(
            rule_id="RULE-01-MAX-CRITICAL",
            title="Maximum Permitted Critical Vulnerabilities",
            status="PASS" if r1_pass else "FAIL",
            severity="CRITICAL",
            threshold=config.max_critical_findings,
            observed_value=critical_count,
            message=f"Observed {critical_count} critical findings (threshold: <= {config.max_critical_findings})"
        ))

        # Rule 2: Max High Findings
        r2_pass = high_count <= config.max_high_findings
        if not r2_pass:
            for f in active_findings:
                if f.original_severity == FindingSeverity.HIGH:
                    blocking_ids.add(f.id)
        rule_results.append(PolicyRuleResult(
            rule_id="RULE-02-MAX-HIGH",
            title="Maximum Permitted High Severity Vulnerabilities",
            status="PASS" if r2_pass else "FAIL",
            severity="HIGH",
            threshold=config.max_high_findings,
            observed_value=high_count,
            message=f"Observed {high_count} high findings (threshold: <= {config.max_high_findings})"
        ))

        # Rule 3: Hardcoded Secrets Policy
        r3_pass = (len(secret_findings) == 0) or config.allow_unresolved_secrets
        if not r3_pass:
            for f in secret_findings:
                blocking_ids.add(f.id)
        rule_results.append(PolicyRuleResult(
            rule_id="RULE-03-ZERO-SECRETS",
            title="Zero Unmitigated Hardcoded Secrets",
            status="PASS" if r3_pass else "FAIL",
            severity="CRITICAL",
            threshold=0 if not config.allow_unresolved_secrets else "PERMITTED",
            observed_value=len(secret_findings),
            message=f"Found {len(secret_findings)} active credential leak(s) in repository"
        ))

        # Rule 4: Maximum Single CVSS Score
        r4_pass = len(high_cvss_findings) == 0
        if not r4_pass:
            for f in high_cvss_findings:
                blocking_ids.add(f.id)
        rule_results.append(PolicyRuleResult(
            rule_id="RULE-04-MAX-CVSS",
            title="Maximum Single CVSS Threshold",
            status="PASS" if r4_pass else "FAIL",
            severity="HIGH",
            threshold=config.max_cvss_threshold,
            observed_value=max([f.cvss_score or 0.0 for f in active_findings], default=0.0),
            message=f"Detected {len(high_cvss_findings)} finding(s) with CVSS >= {config.max_cvss_threshold}"
        ))

        # Rule 5: Project Overall Risk Ceiling
        r5_pass = avg_risk_score <= config.max_risk_score
        rule_results.append(PolicyRuleResult(
            rule_id="RULE-05-RISK-CEILING",
            title="Project Aggregate Risk Ceiling",
            status="PASS" if r5_pass else "WARN",
            severity="MEDIUM",
            threshold=config.max_risk_score,
            observed_value=avg_risk_score,
            message=f"Project average risk score is {avg_risk_score} (ceiling: {config.max_risk_score})"
        ))

        # Rule 6: Production Asset Exposure Security (TLS / Public exposure check)
        public_assets = [a for a in assets if a.exposure == AssetExposure.INTERNET_FACING]
        config_findings = [f for f in active_findings if f.category == FindingCategory.CONFIG and "TLS" in f.title.upper()]
        r6_pass = True
        if config.enforce_production_tls and public_assets and config_findings:
            r6_pass = False
            for f in config_findings:
                blocking_ids.add(f.id)

        rule_results.append(PolicyRuleResult(
            rule_id="RULE-06-ENFORCE-TLS",
            title="Enforce Secure Transport on Internet-Facing Assets",
            status="PASS" if r6_pass else "FAIL",
            severity="HIGH",
            threshold="TLS 1.2+ Required",
            observed_value=f"{len(config_findings)} TLS violation(s)",
            message="Public assets must not have active insecure transport or missing TLS configurations"
        ))

        # Determine overall status
        failed_critical_high = any(r.status == "FAIL" for r in rule_results)
        failed_warnings = any(r.status == "WARN" for r in rule_results)

        if failed_critical_high:
            overall_status = PolicyStatus.FAILED
            summary = f"Build gate policy FAILED: {len(blocking_ids)} blocking vulnerability finding(s) exceed security thresholds."
        elif failed_warnings:
            overall_status = PolicyStatus.WARNING
            summary = "Build gate policy passed with WARNINGS: Aggregate risk is elevated but no blocking thresholds breached."
        else:
            overall_status = PolicyStatus.PASSED
            summary = "Build gate policy PASSED: All security rules satisfied."

        return PolicyEvaluationResult(
            project_id=project_id,
            overall_status=overall_status,
            summary=summary,
            evaluated_at=datetime.now(timezone.utc).isoformat(),
            engine_version=cls.ENGINE_VERSION,
            total_active_findings=len(active_findings),
            blocking_findings_count=len(blocking_ids),
            rule_results=rule_results,
            blocking_finding_ids=list(blocking_ids)
        )


policy_engine = PolicyEngine()
