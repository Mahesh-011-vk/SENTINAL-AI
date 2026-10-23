import time
from datetime import datetime, timezone
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from app.models.scan import ScanJob, ScanStatus, ScanType, ScannerName, ScannerExecution, ScannerExecutionStatus
from app.models.finding import Finding, FindingEvidence, FindingStatus
from app.models.asset import Asset
from app.scanners.base import BaseScannerAdapter, ScannerResult, NormalizedFindingData
from app.scanners.sast_semgrep import SemgrepSASTAdapter
from app.scanners.secret_gitleaks import GitleaksSecretAdapter
from app.scanners.sca_osv import OSVScannerSCAAdapter
from app.scanners.config_audit import ConfigAuditAdapter
from app.scanners.dast_zap import OWASPZAPAdapter
from app.scanners.mock_adapter import MockScannerAdapter
from app.services.risk_service import DeterministicRiskEngine
from app.services.audit_service import AuditService


class ScannerManager:
    """
    Coordinates scanner execution, evidence normalization, deduplication,
    deterministic risk scoring, and audit logging.
    """

    def __init__(self):
        self.adapters: Dict[ScannerName, BaseScannerAdapter] = {
            ScannerName.SEMGREP: SemgrepSASTAdapter(),
            ScannerName.GITLEAKS: GitleaksSecretAdapter(),
            ScannerName.OSV_SCANNER: OSVScannerSCAAdapter(),
            ScannerName.CONFIG_AUDIT: ConfigAuditAdapter(),
            ScannerName.OWASP_ZAP: OWASPZAPAdapter(),
            ScannerName.MOCK_SCANNER: MockScannerAdapter(),
        }

    def get_adapter(self, name: ScannerName) -> BaseScannerAdapter:
        return self.adapters.get(name, self.adapters[ScannerName.MOCK_SCANNER])

    def determine_scanners_for_job(self, scan_type: ScanType) -> List[ScannerName]:
        if scan_type == ScanType.FULL:
            return [ScannerName.SEMGREP, ScannerName.GITLEAKS, ScannerName.OSV_SCANNER, ScannerName.CONFIG_AUDIT]
        elif scan_type == ScanType.SAST:
            return [ScannerName.SEMGREP]
        elif scan_type == ScanType.SECRET:
            return [ScannerName.GITLEAKS]
        elif scan_type == ScanType.SCA:
            return [ScannerName.OSV_SCANNER]
        elif scan_type == ScanType.DAST:
            return [ScannerName.OWASP_ZAP, ScannerName.CONFIG_AUDIT]
        elif scan_type == ScanType.CONFIG:
            return [ScannerName.CONFIG_AUDIT]
        return [ScannerName.SEMGREP]

    def execute_scan_job(
        self,
        db: Session,
        scan_job_id: str,
        options: Optional[Dict] = None
    ) -> ScanJob:
        """
        Execute an orchestrated scan job synchronously or worker-dispatched.
        Transitions job state, persists scanner executions and normalized findings.
        """
        job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if not job:
            raise ValueError(f"ScanJob {scan_job_id} not found")

        asset: Asset = job.asset
        now = datetime.now(timezone.utc)
        job.status = ScanStatus.RUNNING
        job.started_at = now
        db.commit()

        scanners_to_run = self.determine_scanners_for_job(job.scan_type)
        total_findings = 0
        failed_scanners = 0

        for s_name in scanners_to_run:
            adapter = self.get_adapter(s_name)
            is_avail, ver = adapter.check_availability()
            
            # Execute scanner
            result: ScannerResult = adapter.scan(
                target=asset.target_locator,
                timeout_seconds=300,
                options=options
            )

            # Persist ScannerExecution record
            execution = ScannerExecution(
                scan_job_id=job.id,
                scanner_name=s_name,
                scanner_version=result.scanner_version,
                status=result.status,
                exit_code=result.exit_code,
                execution_time_seconds=result.execution_time_seconds,
                error_log=result.error_log
            )
            db.add(execution)

            if result.status != ScannerExecutionStatus.SUCCESS:
                failed_scanners += 1

            # Ingest and normalize findings
            for nf in result.findings:
                # Check for existing finding with same fingerprint in project
                existing = db.query(Finding).filter(
                    Finding.project_id == job.project_id,
                    Finding.fingerprint == nf.fingerprint
                ).first()

                if existing:
                    # Deduplication / recurrence
                    existing.last_seen_at = now
                    existing.scan_job_id = job.id
                    if existing.status == FindingStatus.VERIFIED_RESOLVED:
                        existing.status = FindingStatus.REOPENED
                    total_findings += 1
                else:
                    # Calculate deterministic risk score v1.0.0
                    score, level, rationale, _ = DeterministicRiskEngine.calculate_risk(
                        severity=nf.severity,
                        asset_criticality=asset.business_criticality,
                        asset_exposure=asset.exposure
                    )

                    new_finding = Finding(
                        project_id=job.project_id,
                        asset_id=asset.id,
                        scan_job_id=job.id,
                        fingerprint=nf.fingerprint,
                        title=nf.title,
                        description=nf.description,
                        category=nf.category,
                        scanner_name=nf.scanner_name,
                        scanner_rule_id=nf.scanner_rule_id,
                        cwe_id=nf.cwe_id,
                        original_severity=nf.severity,
                        cvss_score=nf.cvss_score,
                        cvss_vector=nf.cvss_vector,
                        internal_risk_level=level,
                        internal_risk_score=score,
                        risk_rationale=rationale,
                        status=FindingStatus.OPEN,
                        first_seen_at=now,
                        last_seen_at=now
                    )
                    db.add(new_finding)
                    db.flush()

                    evidence = FindingEvidence(
                        finding_id=new_finding.id,
                        evidence_type=nf.evidence_type,
                        file_path=nf.file_path,
                        start_line=nf.start_line,
                        end_line=nf.end_line,
                        sanitized_snippet=nf.sanitized_evidence,
                        raw_hash=nf.raw_hash
                    )
                    db.add(evidence)
                    total_findings += 1

        # Determine overall scan job status
        job.completed_at = datetime.now(timezone.utc)
        if failed_scanners == 0:
            job.status = ScanStatus.COMPLETED
        elif failed_scanners < len(scanners_to_run):
            job.status = ScanStatus.PARTIAL_SUCCESS
            job.error_message = f"{failed_scanners} of {len(scanners_to_run)} scanners failed or timed out."
        else:
            job.status = ScanStatus.FAILED
            job.error_message = "All executed security scanners failed."

        db.commit()
        db.refresh(job)

        # Log audit event
        AuditService.log_event(
            db=db,
            tenant_id=job.project.tenant_id,
            action="SCAN_COMPLETED",
            resource_type="SCAN_JOB",
            resource_id=job.id,
            details={
                "status": job.status.value,
                "findings_count": total_findings,
                "scanners_executed": [s.value for s in scanners_to_run]
            }
        )

        return job


scanner_manager = ScannerManager()
