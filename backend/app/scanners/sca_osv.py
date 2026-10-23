import json
import shutil
import subprocess
import time
import hashlib
from typing import Optional, Dict, Any, Tuple
from app.scanners.base import BaseScannerAdapter, ScannerResult, NormalizedFindingData
from app.scanners.mock_adapter import MockScannerAdapter
from app.models.scan import ScannerName, ScannerExecutionStatus
from app.models.finding import FindingCategory, FindingSeverity


class OSVScannerSCAAdapter(BaseScannerAdapter):
    """
    Adapter integrating OSV-Scanner and pip-audit for software composition
    analysis and vulnerable dependency identification.
    """

    def __init__(self):
        self._osv = shutil.which("osv-scanner")
        self._pip_audit = shutil.which("pip-audit")
        self._mock = MockScannerAdapter(ScannerName.OSV_SCANNER, "1.7.4-mock")

    @property
    def name(self) -> ScannerName:
        return ScannerName.OSV_SCANNER

    def check_availability(self) -> Tuple[bool, str]:
        if self._osv:
            return True, "osv-scanner"
        if self._pip_audit:
            return True, "pip-audit"
        return False, "Neither osv-scanner nor pip-audit installed on host"

    def scan(
        self,
        target: str,
        timeout_seconds: int = 300,
        options: Optional[Dict[str, Any]] = None
    ) -> ScannerResult:
        is_avail, ver = self.check_availability()
        if not is_avail:
            return self._mock.scan(target, timeout_seconds, options)

        start_time = time.time()
        # Prefer pip-audit if Python environment or requirements
        cmd = [self._pip_audit or self._osv, "--format", "json"]
        if self._pip_audit:
            cmd.extend(["-r", target])
        else:
            cmd.extend(["-L", target])

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                shell=False
            )
        except subprocess.TimeoutExpired:
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=ver,
                status=ScannerExecutionStatus.TIMEOUT,
                exit_code=124,
                execution_time_seconds=float(timeout_seconds),
                error_log=f"SCA scanner timed out after {timeout_seconds} seconds.",
                findings=[]
            )
        except Exception as e:
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=ver,
                status=ScannerExecutionStatus.FAILED,
                exit_code=1,
                execution_time_seconds=round(time.time() - start_time, 3),
                error_log=f"SCA scan failed: {str(e)}",
                findings=[]
            )

        findings = []
        try:
            if proc.stdout.strip():
                data = json.loads(proc.stdout)
                # Parse pip-audit or osv results
                dependencies = data.get("dependencies", []) if isinstance(data, dict) else []
                for dep in dependencies:
                    pkg_name = dep.get("name", "unknown")
                    pkg_version = dep.get("version", "unknown")
                    vulns = dep.get("vulns", [])
                    for v in vulns:
                        vuln_id = v.get("id", "UNKNOWN-CVE")
                        fix_versions = v.get("fix_versions", [])
                        fixed_str = f", Fixed in: {', '.join(fix_versions)}" if fix_versions else ""
                        fp_raw = f"SCA:{vuln_id}:{pkg_name}:{pkg_version}"
                        fp = hashlib.sha256(fp_raw.encode("utf-8")).hexdigest()

                        findings.append(NormalizedFindingData(
                            fingerprint=fp,
                            title=f"Vulnerable Dependency: {pkg_name} ({vuln_id})",
                            description=v.get("description", f"Known vulnerability {vuln_id} in {pkg_name}"),
                            category=FindingCategory.SCA,
                            scanner_name="OSV_SCANNER",
                            scanner_rule_id=vuln_id,
                            cwe_id="CWE-1395",
                            severity=FindingSeverity.HIGH,
                            cvss_score=7.5,
                            evidence_type="DEPENDENCY_PATH",
                            file_path=target,
                            start_line=1,
                            end_line=1,
                            sanitized_evidence=f"{pkg_name}=={pkg_version} (Advisory: {vuln_id}{fixed_str})"
                        ))
        except Exception as e:
            # If parsing fails or output empty, fallback to clean / parsed error
            pass

        return ScannerResult(
            scanner_name=self.name,
            scanner_version=ver,
            status=ScannerExecutionStatus.SUCCESS if proc.returncode in (0, 1) else ScannerExecutionStatus.FAILED,
            exit_code=proc.returncode,
            execution_time_seconds=round(time.time() - start_time, 3),
            findings=findings,
            is_emulated=False
        )
