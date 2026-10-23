import pytest
import json
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.tenant import Tenant
from app.models.project import Project
from app.models.asset import Asset, AssetType, EnvironmentType, AssetExposure, BusinessCriticality
from app.models.finding import Finding, FindingCategory, FindingSeverity, FindingStatus
from app.services.sbom_service import SBOMService
from app.services.policy_engine import PolicyEngine, PolicyConfig, PolicyStatus
from app.scanners.api_spec_audit import APISpecAuditAdapter
from app.models.scan import ScannerExecutionStatus


@pytest.fixture
def test_project(db: Session, tenant_alpha: Tenant) -> Project:
    project = Project(
        tenant_id=tenant_alpha.id,
        name="Payments Gateway",
        description="Core PCI-DSS financial gateway"
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@pytest.fixture
def test_asset(db: Session, test_project: Project) -> Asset:
    asset = Asset(
        project_id=test_project.id,
        name="payment-api",
        asset_type=AssetType.WEB_APPLICATION,
        environment=EnvironmentType.PRODUCTION,
        business_criticality=BusinessCriticality.CRITICAL,
        exposure=AssetExposure.INTERNET_FACING,
        target_locator="https://payment.example.com"
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def test_sbom_generation(db: Session, test_project: Project, test_asset: Asset):
    """Verify CycloneDX 1.5 JSON SBOM generation with components and metadata."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)

    sca_finding = Finding(
        project_id=test_project.id,
        asset_id=test_asset.id,
        scan_job_id="dummy-job-1",
        fingerprint="sca-fingerprint-test",
        title="Vulnerable requests library CVE-2023-32681",
        description="Leaked Proxy-Authorization header during redirect",
        category=FindingCategory.SCA,
        scanner_name="OSV_SCANNER",
        scanner_rule_id="CVE-2023-32681",
        cwe_id="CWE-200",
        original_severity=FindingSeverity.HIGH,
        cvss_score=6.1,
        status=FindingStatus.OPEN,
        first_seen_at=now,
        last_seen_at=now
    )
    db.add(sca_finding)
    db.commit()

    sbom = SBOMService.generate_cyclonedx_sbom(db=db, project_id=test_project.id)

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert "serialNumber" in sbom
    assert sbom["metadata"]["component"]["name"] == test_project.name
    assert len(sbom["components"]) >= 1
    assert any(c["name"] == test_asset.name for c in sbom["components"])
    assert len(sbom["vulnerabilities"]) >= 1
    assert sbom["vulnerabilities"][0]["id"] == "CVE-2023-32681"


def test_policy_engine_evaluation(db: Session, test_project: Project, test_asset: Asset):
    """Verify deterministic policy engine evaluations under different conditions."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)

    # 1. Clean project -> PASSED
    eval_clean = PolicyEngine.evaluate(db=db, project_id=test_project.id)
    assert eval_clean.overall_status == PolicyStatus.PASSED
    assert eval_clean.blocking_findings_count == 0

    # 2. Add Critical finding -> FAILED
    crit_finding = Finding(
        project_id=test_project.id,
        asset_id=test_asset.id,
        scan_job_id="dummy-job-2",
        fingerprint="crit-fp-test",
        title="SQL Injection in auth",
        description="Unsanitized query in user auth",
        category=FindingCategory.SAST,
        scanner_name="SEMGREP",
        scanner_rule_id="python.lang.security.audit.sqli",
        cwe_id="CWE-89",
        original_severity=FindingSeverity.CRITICAL,
        cvss_score=9.8,
        status=FindingStatus.OPEN,
        first_seen_at=now,
        last_seen_at=now
    )
    db.add(crit_finding)
    db.commit()

    eval_failed = PolicyEngine.evaluate(db=db, project_id=test_project.id)
    assert eval_failed.overall_status == PolicyStatus.FAILED
    assert eval_failed.blocking_findings_count == 1
    assert crit_finding.id in eval_failed.blocking_finding_ids

    # 3. Custom lenient threshold -> PASSED
    lenient_config = PolicyConfig(max_critical_findings=5, max_risk_score=99.0, max_cvss_threshold=10.0)
    eval_lenient = PolicyEngine.evaluate(db=db, project_id=test_project.id, config=lenient_config)
    assert eval_lenient.overall_status == PolicyStatus.PASSED


def test_api_spec_audit_vulnerable_spec():
    """Verify APISpecAuditAdapter detects security weaknesses in OpenAPI schemas."""
    vulnerable_spec = {
        "openapi": "3.0.3",
        "info": {"title": "Insecure Payment API", "version": "1.0.0"},
        "servers": [{"url": "http://api.insecure-payments.com/v1"}],
        "paths": {
            "/transfer": {
                "post": {
                    "summary": "Transfer funds",
                    "parameters": [
                        {
                            "name": "token",
                            "in": "query",
                            "required": True,
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Success",
                            "headers": {
                                "Access-Control-Allow-Origin": {
                                    "schema": {"type": "string", "example": "*"}
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    adapter = APISpecAuditAdapter()
    result = adapter.scan(target=json.dumps(vulnerable_spec))

    assert result.status == ScannerExecutionStatus.SUCCESS
    assert len(result.findings) >= 4

    rule_ids = [f.scanner_rule_id for f in result.findings]
    assert "API-SEC-01-MISSING-SCHEMES" in rule_ids
    assert "API-SEC-02-INSECURE-HTTP" in rule_ids
    assert "API-SEC-03-UNAUTHENTICATED-MUTATION" in rule_ids
    assert "API-SEC-04-QUERY-CREDENTIAL" in rule_ids
    assert "API-SEC-05-WILDCARD-CORS" in rule_ids


def test_api_spec_audit_clean_spec():
    """Verify APISpecAuditAdapter produces no findings on a hardened OpenAPI schema."""
    hardened_spec = {
        "openapi": "3.0.3",
        "info": {"title": "Secure Banking API", "version": "2.0.0"},
        "servers": [{"url": "https://api.secure-bank.io/v2"}],
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                }
            }
        },
        "security": [{"BearerAuth": []}],
        "paths": {
            "/accounts": {
                "get": {
                    "summary": "List customer accounts",
                    "responses": {"200": {"description": "Account list"}}
                }
            }
        }
    }

    adapter = APISpecAuditAdapter()
    result = adapter.scan(target=json.dumps(hardened_spec))

    assert result.status == ScannerExecutionStatus.SUCCESS
    assert len(result.findings) == 0


def test_sbom_and_policy_api_endpoints(client: TestClient, secadmin_token: str, test_project: Project):
    """Verify HTTP API endpoints for SBOM retrieval and Policy evaluation."""
    headers = {"Authorization": f"Bearer {secadmin_token}"}

    # Test GET /projects/{id}/sbom
    sbom_resp = client.get(f"/api/v1/projects/{test_project.id}/sbom", headers=headers)
    assert sbom_resp.status_code == 200
    sbom_data = sbom_resp.json()
    assert sbom_data["bomFormat"] == "CycloneDX"

    # Test POST /projects/{id}/policy/evaluate
    policy_resp = client.post(
        f"/api/v1/projects/{test_project.id}/policy/evaluate",
        headers=headers,
        json={"max_critical_findings": 0, "max_high_findings": 1}
    )
    assert policy_resp.status_code == 200
    policy_data = policy_resp.json()
    assert policy_data["overall_status"] in ["PASSED", "FAILED", "WARNING"]
    assert "rule_results" in policy_data
    assert len(policy_data["rule_results"]) == 6
