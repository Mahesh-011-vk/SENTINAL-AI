import hashlib
import time
from typing import List, Optional, Dict, Any, Tuple
from app.scanners.base import BaseScannerAdapter, ScannerResult, NormalizedFindingData
from app.models.scan import ScannerName, ScannerExecutionStatus
from app.models.finding import FindingCategory, FindingSeverity
from app.core.redactor import SecretRedactor


class MockScannerAdapter(BaseScannerAdapter):
    """
    Test double and fallback emulator for environments without installed
    scanner binaries. Provides reproducible, evidence-backed findings and
    supports deterministic failure/timeout simulations.
    """

    def __init__(self, scanner_name: ScannerName = ScannerName.MOCK_SCANNER, mock_version: str = "1.0.0-mock"):
        self._name = scanner_name
        self._version = mock_version

    @property
    def name(self) -> ScannerName:
        return self._name

    def check_availability(self) -> Tuple[bool, str]:
        return True, self._version

    def _generate_fingerprint(self, category: str, rule_id: str, path: str, extra: str) -> str:
        raw = f"{category}:{rule_id}:{path}:{extra}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def scan(
        self,
        target: str,
        timeout_seconds: int = 300,
        options: Optional[Dict[str, Any]] = None
    ) -> ScannerResult:
        opts = options or {}
        start_time = time.time()

        # Check for simulated timeout
        if opts.get("simulate_timeout"):
            return ScannerResult(
                scanner_name=self._name,
                scanner_version=self._version,
                status=ScannerExecutionStatus.TIMEOUT,
                exit_code=124,
                execution_time_seconds=float(timeout_seconds),
                error_log="Execution timed out after 300 seconds limit.",
                findings=[],
                is_emulated=True
            )

        # Check for simulated failure
        if opts.get("simulate_failure"):
            return ScannerResult(
                scanner_name=self._name,
                scanner_version=self._version,
                status=ScannerExecutionStatus.FAILED,
                exit_code=1,
                execution_time_seconds=0.15,
                error_log="Scanner execution failed: Syntax error in configuration file or fatal binary exit.",
                findings=[],
                is_emulated=True
            )

        # Generate realistic findings according to requested category/scanner
        findings: List[NormalizedFindingData] = []
        scanner_type = opts.get("category", self._name.value)

        if self._name == ScannerName.SEMGREP or scanner_type == "SAST":
            raw_code = "cursor.execute(f'SELECT * FROM users WHERE username = \"{user_input}\"')"
            sanitized = SecretRedactor.redact(raw_code)
            fp = self._generate_fingerprint("SAST", "python.sqlalchemy.injection", "app/api/auth.py", "42")
            findings.append(NormalizedFindingData(
                fingerprint=fp,
                title="SQL Injection via Unsanitized Formatting",
                description="User input is directly interpolated into raw SQL query without parameterized statements.",
                category=FindingCategory.SAST,
                scanner_name="SEMGREP",
                scanner_rule_id="python.sqlalchemy.injection.raw-format",
                cwe_id="CWE-89",
                severity=FindingSeverity.CRITICAL,
                cvss_score=8.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                evidence_type="CODE_SNIPPET",
                file_path="app/api/auth.py",
                start_line=42,
                end_line=44,
                sanitized_evidence=sanitized
            ))

        elif self._name == ScannerName.GITLEAKS or scanner_type == "SECRET":
            raw_secret = 'AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
            sanitized = SecretRedactor.redact(raw_secret)
            fp = self._generate_fingerprint("SECRET", "aws-secret-access-key", "config/aws.py", "10")
            findings.append(NormalizedFindingData(
                fingerprint=fp,
                title="Exposed Hardcoded AWS Secret Access Key",
                description="Hardcoded AWS secret key discovered in repository configuration.",
                category=FindingCategory.SECRET,
                scanner_name="GITLEAKS",
                scanner_rule_id="aws-secret-access-key",
                cwe_id="CWE-798",
                severity=FindingSeverity.HIGH,
                cvss_score=7.4,
                evidence_type="SECRET_MATCH",
                file_path="config/aws.py",
                start_line=10,
                end_line=10,
                sanitized_evidence=sanitized
            ))

        elif self._name == ScannerName.OSV_SCANNER or scanner_type == "SCA":
            fp = self._generate_fingerprint("SCA", "GHSA-j8r2-6x86-q33q", "requirements.txt", "requests@2.28.1")
            findings.append(NormalizedFindingData(
                fingerprint=fp,
                title="Requests: Proxy-Authorization Header Leak",
                description="Requests forwards Proxy-Authorization header across origin redirects.",
                category=FindingCategory.SCA,
                scanner_name="OSV_SCANNER",
                scanner_rule_id="GHSA-j8r2-6x86-q33q",
                cwe_id="CWE-200",
                severity=FindingSeverity.HIGH,
                cvss_score=6.1,
                evidence_type="DEPENDENCY_PATH",
                file_path="requirements.txt",
                start_line=5,
                end_line=5,
                sanitized_evidence="requests==2.28.1 (Affected: <2.31.0, Fixed: 2.31.0)"
            ))

        elif self._name == ScannerName.CONFIG_AUDIT or scanner_type == "CONFIG":
            fp = self._generate_fingerprint("CONFIG", "missing-hsts-header", target, "443")
            findings.append(NormalizedFindingData(
                fingerprint=fp,
                title="Strict-Transport-Security Header Not Enforced",
                description="The target web endpoint does not supply a Strict-Transport-Security (HSTS) response header.",
                category=FindingCategory.CONFIG,
                scanner_name="CONFIG_AUDIT",
                scanner_rule_id="http-header-missing-hsts",
                cwe_id="CWE-693",
                severity=FindingSeverity.LOW,
                cvss_score=3.1,
                evidence_type="HTTP_TRACE",
                file_path=target,
                start_line=1,
                end_line=1,
                sanitized_evidence="HTTP/1.1 200 OK\nMissing: Strict-Transport-Security\nServer: nginx"
            ))

        elif self._name == ScannerName.OWASP_ZAP or scanner_type == "DAST":
            fp = self._generate_fingerprint("DAST", "anti-clickjacking-xfo", target, "index")
            findings.append(NormalizedFindingData(
                fingerprint=fp,
                title="Missing Anti-Clickjacking Header (X-Frame-Options)",
                description="Target response lacks X-Frame-Options or Content-Security-Policy frame-ancestors directive.",
                category=FindingCategory.DAST,
                scanner_name="OWASP_ZAP",
                scanner_rule_id="zap-rule-10020",
                cwe_id="CWE-1021",
                severity=FindingSeverity.MEDIUM,
                cvss_score=4.3,
                evidence_type="HTTP_TRACE",
                file_path=target,
                start_line=1,
                end_line=1,
                sanitized_evidence=f"GET {target} HTTP/1.1\nResponse missing X-Frame-Options header"
            ))

        execution_duration = round(time.time() - start_time + 0.05, 3)

        return ScannerResult(
            scanner_name=self._name,
            scanner_version=self._version,
            status=ScannerExecutionStatus.SUCCESS,
            exit_code=0,
            execution_time_seconds=execution_duration,
            error_log=None,
            findings=findings,
            is_emulated=True
        )
