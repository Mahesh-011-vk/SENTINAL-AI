"""
SentinelAI Demo Seeding Script
Populates clearly labeled demo organizational data, assets, authorization records,
scans, and evidence-backed findings.
"""
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.tenant import Tenant
from app.models.user import User, UserRole
from app.models.project import Project
from app.models.asset import Asset, AssetType, EnvironmentType, BusinessCriticality, AssetExposure, AssetAuthorization
from app.models.scan import ScanJob, ScanType, ScanStatus, ScannerName, ScannerExecution, ScannerExecutionStatus
from app.models.finding import (
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    FindingEvidence,
)
from app.core.security import hash_password
from app.services.risk_service import DeterministicRiskEngine


def seed_demo_data():
    db: Session = SessionLocal()
    try:
        # Check if already seeded
        existing_tenant = db.query(Tenant).filter(Tenant.slug == "demo-security-org").first()
        if existing_tenant:
            print("Demo data already seeded.")
            return

        print("Seeding SentinelAI Demo Data...")
        now = datetime.now(timezone.utc)

        # 1. Organization
        tenant = Tenant(name="Demo Security Org", slug="demo-security-org", is_active=True)
        db.add(tenant)
        db.flush()

        # 2. Users
        secadmin = User(
            tenant_id=tenant.id,
            email="admin@sentinelai.io",
            hashed_password=hash_password("AdminPass123!"),
            full_name="Sarah Connor (Security Admin)",
            role=UserRole.SECURITY_ADMIN,
            is_active=True
        )
        engineer = User(
            tenant_id=tenant.id,
            email="engineer@sentinelai.io",
            hashed_password=hash_password("DevPass123!"),
            full_name="Devon Miles (Lead Engineer)",
            role=UserRole.ENGINEER,
            is_active=True
        )
        auditor = User(
            tenant_id=tenant.id,
            email="auditor@sentinelai.io",
            hashed_password=hash_password("AuditPass123!"),
            full_name="Elena Vance (Compliance Auditor)",
            role=UserRole.AUDITOR,
            is_active=True
        )
        db.add_all([secadmin, engineer, auditor])
        db.flush()

        # 3. Project
        project = Project(
            tenant_id=tenant.id,
            name="Nexus Enterprise Services",
            description="Core financial and authentication web applications and APIs"
        )
        db.add(project)
        db.flush()

        # 4. Assets
        repo_asset = Asset(
            project_id=project.id,
            name="nexus-core-backend",
            asset_type=AssetType.REPOSITORY,
            target_locator="https://github.com/sentinel-demo/nexus-core",
            environment=EnvironmentType.PRODUCTION,
            business_criticality=BusinessCriticality.CRITICAL,
            exposure=AssetExposure.INTERNAL
        )
        web_asset = Asset(
            project_id=project.id,
            name="Nexus Customer Portal",
            asset_type=AssetType.WEB_APPLICATION,
            target_locator="https://portal.nexus.demo.internal",
            environment=EnvironmentType.PRODUCTION,
            business_criticality=BusinessCriticality.CRITICAL,
            exposure=AssetExposure.INTERNET_FACING
        )
        db.add_all([repo_asset, web_asset])
        db.flush()

        # 5. Asset Authorization (Signed by SecAdmin)
        auth_record = AssetAuthorization(
            asset_id=web_asset.id,
            authorized_by_id=secadmin.id,
            scope_description="Authorized production web assessment for quarterly security audit",
            allowed_domains="portal.nexus.demo.internal,api.nexus.demo.internal",
            expires_at=now + timedelta(days=90),
            is_revoked=False
        )
        db.add(auth_record)
        db.flush()

        # 6. Completed Scan Job
        scan_job = ScanJob(
            project_id=project.id,
            asset_id=repo_asset.id,
            triggered_by_id=engineer.id,
            scan_type=ScanType.FULL,
            status=ScanStatus.COMPLETED,
            started_at=now - timedelta(minutes=15),
            completed_at=now - timedelta(minutes=10)
        )
        db.add(scan_job)
        db.flush()

        # Scanner Executions
        exec_sast = ScannerExecution(
            scan_job_id=scan_job.id,
            scanner_name=ScannerName.SEMGREP,
            scanner_version="1.85.0",
            status=ScannerExecutionStatus.SUCCESS,
            exit_code=0,
            execution_time_seconds=12.4
        )
        exec_secret = ScannerExecution(
            scan_job_id=scan_job.id,
            scanner_name=ScannerName.GITLEAKS,
            scanner_version="8.18.4",
            status=ScannerExecutionStatus.SUCCESS,
            exit_code=0,
            execution_time_seconds=4.2
        )
        exec_sca = ScannerExecution(
            scan_job_id=scan_job.id,
            scanner_name=ScannerName.OSV_SCANNER,
            scanner_version="1.7.4",
            status=ScannerExecutionStatus.SUCCESS,
            exit_code=0,
            execution_time_seconds=8.1
        )
        db.add_all([exec_sast, exec_secret, exec_sca])
        db.flush()

        # 7. Evidence-Backed Findings
        # Finding 1: SQL Injection (SAST)
        s1, l1, r1, _ = DeterministicRiskEngine.calculate_risk(
            severity=FindingSeverity.CRITICAL,
            asset_criticality=repo_asset.business_criticality,
            asset_exposure=repo_asset.exposure,
            exploitability_factor=1.2
        )
        f1 = Finding(
            project_id=project.id,
            asset_id=repo_asset.id,
            scan_job_id=scan_job.id,
            fingerprint="fp_sql_injection_users_auth_py_42",
            title="Improper Neutralization of Special Elements in SQL Command (SQL Injection)",
            description="User input from login request is concatenated directly into SQL statement without parameterized placeholders.",
            category=FindingCategory.SAST,
            scanner_name="SEMGREP",
            scanner_rule_id="python.sqlalchemy.security.injection.raw-sql-concat",
            cwe_id="CWE-89",
            original_severity=FindingSeverity.CRITICAL,
            cvss_score=8.9,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            internal_risk_level=l1,
            internal_risk_score=s1,
            risk_rationale=r1,
            status=FindingStatus.OPEN,
            first_seen_at=now,
            last_seen_at=now
        )
        db.add(f1)
        db.flush()

        ev1 = FindingEvidence(
            finding_id=f1.id,
            evidence_type="CODE_SNIPPET",
            file_path="nexus/auth/service.py",
            start_line=40,
            end_line=45,
            sanitized_snippet="query = f'SELECT id, password_hash FROM accounts WHERE email = \"{user_input}\"'\nresult = db.execute(text(query))"
        )
        db.add(ev1)

        # Finding 2: Leaked AWS Secret Key (Secret)
        s2, l2, r2, _ = DeterministicRiskEngine.calculate_risk(
            severity=FindingSeverity.HIGH,
            asset_criticality=repo_asset.business_criticality,
            asset_exposure=repo_asset.exposure
        )
        f2 = Finding(
            project_id=project.id,
            asset_id=repo_asset.id,
            scan_job_id=scan_job.id,
            fingerprint="fp_secret_aws_key_deploy_sh_12",
            title="Exposed Hardcoded AWS Secret Access Key in Deployment Script",
            description="Static credentials discovered committed into deploy.sh. High risk of cloud account compromise.",
            category=FindingCategory.SECRET,
            scanner_name="GITLEAKS",
            scanner_rule_id="gitleaks-rule-aws-secret-access-key",
            cwe_id="CWE-798",
            original_severity=FindingSeverity.HIGH,
            cvss_score=7.5,
            internal_risk_level=l2,
            internal_risk_score=s2,
            risk_rationale=r2,
            status=FindingStatus.OPEN,
            first_seen_at=now,
            last_seen_at=now
        )
        db.add(f2)
        db.flush()

        ev2 = FindingEvidence(
            finding_id=f2.id,
            evidence_type="SECRET_MATCH",
            file_path="scripts/deploy.sh",
            start_line=12,
            end_line=13,
            sanitized_snippet="export AWS_SECRET_ACCESS_KEY=\"[REDACTED_AWS_SECRET_KEY]\""
        )
        db.add(ev2)

        # Finding 3: Known Vulnerable Dependency (SCA)
        s3, l3, r3, _ = DeterministicRiskEngine.calculate_risk(
            severity=FindingSeverity.HIGH,
            asset_criticality=repo_asset.business_criticality,
            asset_exposure=repo_asset.exposure
        )
        f3 = Finding(
            project_id=project.id,
            asset_id=repo_asset.id,
            scan_job_id=scan_job.id,
            fingerprint="fp_sca_requests_cve_2023_32681",
            title="Unintended Leak of Proxy-Authorization Header in Requests (CVE-2023-32681)",
            description="Requests library prior to 2.31.0 forwards Proxy-Authorization header during cross-origin redirect.",
            category=FindingCategory.SCA,
            scanner_name="OSV_SCANNER",
            scanner_rule_id="GHSA-j8r2-6x86-q33q",
            cwe_id="CWE-200",
            original_severity=FindingSeverity.HIGH,
            cvss_score=6.1,
            internal_risk_level=l3,
            internal_risk_score=s3,
            risk_rationale=r3,
            status=FindingStatus.OPEN,
            first_seen_at=now,
            last_seen_at=now
        )
        db.add(f3)
        db.flush()

        ev3 = FindingEvidence(
            finding_id=f3.id,
            evidence_type="DEPENDENCY_PATH",
            file_path="requirements.txt",
            start_line=18,
            end_line=18,
            sanitized_snippet="requests==2.28.1 (Affected: <2.31.0, Fixed: 2.31.0)"
        )
        db.add(ev3)

        db.commit()
        print("Demo data seeded successfully.")
        print("Admin user: admin@sentinelai.io / AdminPass123!")
        print("Engineer user: engineer@sentinelai.io / DevPass123!")
        print("Auditor user: auditor@sentinelai.io / AuditPass123!")

    except Exception as e:
        db.rollback()
        print(f"Error seeding demo data: {str(e)}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_demo_data()
