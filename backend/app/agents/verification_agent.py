from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.finding import Finding, FindingStatus
from app.models.scan import ScanJob, ScanStatus
from app.models.verification import VerificationRecord, VerificationOutcome


class VerificationAgent:
    """
    Agent 11 — Verification Agent
    Coordinates automated verification of resolved findings following a fix reassessment scan.
    A missing result is verified only if the scanner executed cleanly.
    """

    @classmethod
    def verify_finding(
        cls,
        db: Session,
        finding_id: str,
        verification_scan_id: str
    ) -> VerificationRecord:
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise ValueError(f"Finding {finding_id} not found")

        scan = db.query(ScanJob).filter(ScanJob.id == verification_scan_id).first()
        if not scan:
            raise ValueError(f"ScanJob {verification_scan_id} not found")

        # Check if the scan completed
        if scan.status not in (ScanStatus.COMPLETED, ScanStatus.PARTIAL_SUCCESS):
            record = VerificationRecord(
                finding_id=finding.id,
                scan_job_id=scan.id,
                outcome=VerificationOutcome.INCONCLUSIVE,
                comparison_notes=f"Verification scan status was {scan.status.value}; unable to conclusively evaluate fix."
            )
            db.add(record)
            db.commit()
            return record

        # Check if the finding's fingerprint was detected in the new scan
        still_present = db.query(Finding).filter(
            Finding.project_id == finding.project_id,
            Finding.scan_job_id == scan.id,
            Finding.fingerprint == finding.fingerprint
        ).first()

        now = datetime.now(timezone.utc)
        if still_present:
            outcome = VerificationOutcome.STILL_DETECTED
            notes = (
                f"Vulnerability persists. Finding fingerprint '{finding.fingerprint}' was re-detected "
                f"by scanner in scan cycle {scan.id}."
            )
            finding.status = FindingStatus.REOPENED
            finding.last_seen_at = now
        else:
            outcome = VerificationOutcome.VERIFIED_RESOLVED
            notes = (
                f"Vulnerability verified resolved. Scanner re-assessed target in scan {scan.id} "
                f"and did not detect fingerprint '{finding.fingerprint}'."
            )
            finding.status = FindingStatus.VERIFIED_RESOLVED

        record = VerificationRecord(
            finding_id=finding.id,
            scan_job_id=scan.id,
            outcome=outcome,
            comparison_notes=notes,
            verified_at=now
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record


verification_agent = VerificationAgent()
