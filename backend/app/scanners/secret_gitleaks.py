import json
import shutil
import subprocess
import time
import hashlib
import tempfile
import os
from typing import Optional, Dict, Any, Tuple
from app.scanners.base import BaseScannerAdapter, ScannerResult, NormalizedFindingData
from app.scanners.mock_adapter import MockScannerAdapter
from app.models.scan import ScannerName, ScannerExecutionStatus
from app.models.finding import FindingCategory, FindingSeverity
from app.core.redactor import SecretRedactor


class GitleaksSecretAdapter(BaseScannerAdapter):
    """
    Adapter integrating Gitleaks for secret detection and credential exposure.
    Redacts 100% of detected sensitive values prior to persistence.
    """

    def __init__(self):
        self._binary = shutil.which("gitleaks")
        self._mock = MockScannerAdapter(ScannerName.GITLEAKS, "8.18.4-mock")

    @property
    def name(self) -> ScannerName:
        return ScannerName.GITLEAKS

    def check_availability(self) -> Tuple[bool, str]:
        if not self._binary:
            return False, "Gitleaks CLI not installed on host"
        try:
            res = subprocess.run([self._binary, "version"], capture_output=True, text=True, timeout=5)
            return True, res.stdout.strip()
        except Exception as e:
            return False, f"Failed checking Gitleaks: {str(e)}"

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
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as report_tmp:
            report_path = report_tmp.name

        cmd = [
            self._binary,
            "detect",
            "--no-git",
            "--source", target,
            "--report-format", "json",
            "--report-path", report_path,
            "--exit-code", "0"
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
            if os.path.exists(report_path):
                os.remove(report_path)
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=ver,
                status=ScannerExecutionStatus.TIMEOUT,
                exit_code=124,
                execution_time_seconds=float(timeout_seconds),
                error_log=f"Gitleaks execution timed out after {timeout_seconds} seconds.",
                findings=[]
            )
        except Exception as e:
            if os.path.exists(report_path):
                os.remove(report_path)
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=ver,
                status=ScannerExecutionStatus.FAILED,
                exit_code=1,
                execution_time_seconds=round(time.time() - start_time, 3),
                error_log=f"Failed executing Gitleaks: {str(e)}",
                findings=[]
            )

        findings = []
        try:
            if os.path.exists(report_path) and os.path.getsize(report_path) > 0:
                with open(report_path, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)
                    
                for item in raw_data:
                    rule_id = item.get("RuleID", "generic-secret")
                    file_path = item.get("File", target)
                    start_line = item.get("StartLine", 1)
                    end_line = item.get("EndLine", 1)
                    match_snippet = item.get("Match", "")
                    
                    # 100% secret redaction
                    sanitized_snippet = SecretRedactor.redact(match_snippet)
                    
                    fp_raw = f"SECRET:{rule_id}:{file_path}:{start_line}"
                    fp = hashlib.sha256(fp_raw.encode("utf-8")).hexdigest()

                    findings.append(NormalizedFindingData(
                        fingerprint=fp,
                        title=f"Potential Hardcoded Secret: {item.get('Description', rule_id)}",
                        description=f"Suspected credential detected matching rule '{rule_id}'.",
                        category=FindingCategory.SECRET,
                        scanner_name="GITLEAKS",
                        scanner_rule_id=rule_id,
                        cwe_id="CWE-798",
                        severity=FindingSeverity.HIGH,
                        cvss_score=7.5,
                        evidence_type="SECRET_MATCH",
                        file_path=file_path,
                        start_line=start_line,
                        end_line=end_line,
                        sanitized_evidence=sanitized_snippet
                    ))
        finally:
            if os.path.exists(report_path):
                os.remove(report_path)

        return ScannerResult(
            scanner_name=self.name,
            scanner_version=ver,
            status=ScannerExecutionStatus.SUCCESS,
            exit_code=proc.returncode,
            execution_time_seconds=round(time.time() - start_time, 3),
            findings=findings,
            is_emulated=False
        )
