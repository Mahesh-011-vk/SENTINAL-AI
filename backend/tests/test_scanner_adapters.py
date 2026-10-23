import pytest
from app.models.scan import ScanJob, ScanType, ScanStatus, ScannerName, ScannerExecutionStatus
from app.models.asset import Asset, AssetType, EnvironmentType, BusinessCriticality, AssetExposure
from app.models.project import Project
from app.models.finding import Finding
from app.scanners.mock_adapter import MockScannerAdapter
from app.scanners.config_audit import ConfigAuditAdapter
from app.scanners.manager import scanner_manager


def test_mock_scanner_normal_execution():
    adapter = MockScannerAdapter(ScannerName.SEMGREP)
    res = adapter.scan(target="app/main.py", timeout_seconds=30)
    assert res.status == ScannerExecutionStatus.SUCCESS
    assert res.exit_code == 0
    assert len(res.findings) > 0
    assert res.findings[0].category.value == "SAST"
    assert res.findings[0].evidence_type == "CODE_SNIPPET"


def test_mock_scanner_simulated_timeout():
    adapter = MockScannerAdapter(ScannerName.SEMGREP)
    res = adapter.scan(target="app/main.py", timeout_seconds=10, options={"simulate_timeout": True})
    assert res.status == ScannerExecutionStatus.TIMEOUT
    assert res.exit_code == 124
    assert "timed out" in res.error_log
    assert len(res.findings) == 0


def test_mock_scanner_simulated_failure():
    adapter = MockScannerAdapter(ScannerName.SEMGREP)
    res = adapter.scan(target="app/main.py", timeout_seconds=10, options={"simulate_failure": True})
    assert res.status == ScannerExecutionStatus.FAILED
    assert res.exit_code == 1
    assert "failed" in res.error_log
    assert len(res.findings) == 0


def test_config_audit_blocks_ssrf_target():
    adapter = ConfigAuditAdapter()
    res = adapter.scan(target="http://127.0.0.1:8080")
    assert res.status == ScannerExecutionStatus.FAILED
    assert "SSRF" in res.error_log


def test_scanner_orchestration_and_deduplication(db, tenant_alpha, engineer_user):
    # Setup project and asset
    project = Project(tenant_id=tenant_alpha.id, name="Orchestration Test Project")
    db.add(project)
    db.flush()

    asset = Asset(
        project_id=project.id,
        name="Backend API Service",
        asset_type=AssetType.REPOSITORY,
        target_locator="https://github.com/example/api",
        environment=EnvironmentType.DEVELOPMENT,
        business_criticality=BusinessCriticality.HIGH,
        exposure=AssetExposure.INTERNAL
    )
    db.add(asset)
    db.flush()

    # Create scan job 1
    job1 = ScanJob(
        project_id=project.id,
        asset_id=asset.id,
        triggered_by_id=engineer_user.id,
        scan_type=ScanType.SAST,
        status=ScanStatus.PENDING
    )
    db.add(job1)
    db.commit()

    # Execute scan job 1
    completed_job1 = scanner_manager.execute_scan_job(db, job1.id)
    assert completed_job1.status == ScanStatus.COMPLETED
    assert len(completed_job1.executions) == 1
    assert completed_job1.executions[0].status == ScannerExecutionStatus.SUCCESS
    
    # Verify findings created
    findings_first_run = list(completed_job1.findings)
    assert len(findings_first_run) > 0
    f1 = findings_first_run[0]
    assert f1.internal_risk_score > 0
    first_seen = f1.first_seen_at
    last_seen_1 = f1.last_seen_at

    # Create scan job 2 (same target) to test deduplication
    job2 = ScanJob(
        project_id=project.id,
        asset_id=asset.id,
        triggered_by_id=engineer_user.id,
        scan_type=ScanType.SAST,
        status=ScanStatus.PENDING
    )
    db.add(job2)
    db.commit()

    completed_job2 = scanner_manager.execute_scan_job(db, job2.id)
    assert completed_job2.status == ScanStatus.COMPLETED

    # Verify no duplicate findings created in project
    all_project_findings = db.query(Finding).filter(Finding.project_id == project.id).all()
    assert len(all_project_findings) == len(findings_first_run)
    # last_seen_at should be updated or equal
    assert all_project_findings[0].first_seen_at == first_seen


def test_scanner_failure_is_never_clean_result(db, tenant_alpha, engineer_user):
    project = Project(tenant_id=tenant_alpha.id, name="Failure Handling Project")
    db.add(project)
    db.flush()

    asset = Asset(
        project_id=project.id,
        name="Failing Scanner Test Target",
        asset_type=AssetType.REPOSITORY,
        target_locator="https://github.com/example/fail",
        environment=EnvironmentType.DEVELOPMENT,
        business_criticality=BusinessCriticality.MEDIUM,
        exposure=AssetExposure.INTERNAL
    )
    db.add(asset)
    db.flush()

    job = ScanJob(
        project_id=project.id,
        asset_id=asset.id,
        triggered_by_id=engineer_user.id,
        scan_type=ScanType.SAST,
        status=ScanStatus.PENDING
    )
    db.add(job)
    db.commit()

    # Execute with simulated failure
    completed_job = scanner_manager.execute_scan_job(db, job.id, options={"simulate_failure": True})
    
    # Must NOT be marked COMPLETED
    assert completed_job.status in (ScanStatus.FAILED, ScanStatus.PARTIAL_SUCCESS)
    assert completed_job.executions[0].status == ScannerExecutionStatus.FAILED
    assert completed_job.executions[0].exit_code != 0
    assert "failed" in completed_job.executions[0].error_log.lower()
