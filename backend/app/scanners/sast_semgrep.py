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
from app.core.redactor import SecretRedactor


class SemgrepSASTAdapter(BaseScannerAdapter):
    """
    Adapter integrating Semgrep for static application security testing.
    Executes binary via argument arrays with zero shell interpolation.
    """

    def __init__(self):
        self._binary = shutil.which("semgrep")
        self._mock = MockScannerAdapter(ScannerName.SEMGREP, "1.85.0-mock")

    @property
    def name(self) -> ScannerName:
        return ScannerName.SEMGREP

    def check_availability(self) -> Tuple[bool, str]:
        if not self._binary:
            return False, "Semgrep CLI not installed on host"
        try:
            res = subprocess.run([self._binary, "--version"], capture_output=True, text=True, timeout=5)
            return True, res.stdout.strip()
        except Exception as e:
            return False, f"Failed checking Semgrep: {str(e)}"

    def scan(
        self,
        target: str,
        timeout_seconds: int = 300,
        options: Optional[Dict[str, Any]] = None
    ) -> ScannerResult:
        is_avail, ver = self.check_availability()
        if not is_avail:
            # Graceful test double fallback
            return self._mock.scan(target, timeout_seconds, options)

        start_time = time.time()
        cmd = [
            self._binary,
            "scan",
            "--json",
            "--metrics=off",
            "--config", "auto",
            target
        ]

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
                error_log=f"Semgrep execution timed out after {timeout_seconds} seconds.",
                findings=[]
            )
        except Exception as e:
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=ver,
                status=ScannerExecutionStatus.FAILED,
                exit_code=1,
                execution_time_seconds=round(time.time() - start_time, 3),
                error_log=f"Failed executing Semgrep subprocess: {str(e)}",
                findings=[]
            )

        # Parse JSON output
        findings = []
        try:
            data = json.loads(proc.stdout)
            results = data.get("results", [])
            for r in results:
                check_id = r.get("check_id", "unknown-rule")
                path = r.get("path", target)
                start_line = r.get("start", {}).get("line", 1)
                end_line = r.get("end", {}).get("line", 1)
                raw_lines = r.get("extra", {}).get("lines", "")
                sanitized_snippet = SecretRedactor.redact(raw_lines)
                
                # Deduplication fingerprint
                fp_raw = f"SAST:{check_id}:{path}:{start_line}"
                fp = hashlib.sha256(fp_raw.encode("utf-8")).hexdigest()

                raw_sev = r.get("extra", {}).get("severity", "WARNING").upper()
                sev_map = {
                    "ERROR": FindingSeverity.HIGH,
                    "WARNING": FindingSeverity.MEDIUM,
                    "INFO": FindingSeverity.LOW
                }
                severity = sev_map.get(raw_sev, FindingSeverity.MEDIUM)

                cwe_meta = r.get("extra", {}).get("metadata", {}).get("cwe")
                cwe_id = None
                if isinstance(cwe_meta, list) and cwe_meta:
                    cwe_id = cwe_meta[0]
                elif isinstance(cwe_meta, str):
                    cwe_id = cwe_meta

                findings.append(NormalizedFindingData(
                    fingerprint=fp,
                    title=r.get("extra", {}).get("message", "Semgrep code vulnerability detected").split("\n")[0][:250],
                    description=r.get("extra", {}).get("message", ""),
                    category=FindingCategory.SAST,
                    scanner_name="SEMGREP",
                    scanner_rule_id=check_id,
                    cwe_id=cwe_id,
                    severity=severity,
                    cvss_score=7.0 if severity == FindingSeverity.HIGH else 5.0,
                    evidence_type="CODE_SNIPPET",
                    file_path=path,
                    start_line=start_line,
                    end_line=end_line,
                    sanitized_evidence=sanitized_snippet
                ))

        except Exception as parse_err:
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=ver,
                status=ScannerExecutionStatus.FAILED,
                exit_code=proc.returncode,
                execution_time_seconds=round(time.time() - start_time, 3),
                error_log=f"Failed parsing Semgrep output: {str(parse_err)}\nStderr: {proc.stderr[:1000]}",
                findings=[]
            )

        return ScannerResult(
            scanner_name=self.name,
            scanner_version=ver,
            status=ScannerExecutionStatus.SUCCESS if proc.returncode in (0, 1) else ScannerExecutionStatus.FAILED,
            exit_code=proc.returncode,
            execution_time_seconds=round(time.time() - start_time, 3),
            findings=findings,
            is_emulated=False
        )
