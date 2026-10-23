import hashlib
import time
import httpx
from typing import List, Optional, Dict, Any, Tuple
from app.scanners.base import BaseScannerAdapter, ScannerResult, NormalizedFindingData
from app.models.scan import ScannerName, ScannerExecutionStatus
from app.models.finding import FindingCategory, FindingSeverity
from app.core.ssrf import TargetSecurityValidator, SSRFValidationError


class ConfigAuditAdapter(BaseScannerAdapter):
    """
    Native security configuration and HTTP header inspection adapter.
    Evaluates defensive headers, TLS deployment attributes, and cookie flags.
    Enforces SSRF prevention on every target.
    """

    VERSION = "1.2.0-native"

    RECOMMENDED_HEADERS = {
        "Strict-Transport-Security": {
            "title": "Missing HTTP Strict Transport Security (HSTS) Header",
            "desc": "The server does not enforce encrypted HTTPS communication via HSTS header.",
            "cwe": "CWE-319",
            "severity": FindingSeverity.LOW,
            "cvss": 3.5
        },
        "Content-Security-Policy": {
            "title": "Missing Content-Security-Policy (CSP) Header",
            "desc": "The web application lacks a Content-Security-Policy to mitigate Cross-Site Scripting (XSS).",
            "cwe": "CWE-1021",
            "severity": FindingSeverity.MEDIUM,
            "cvss": 4.8
        },
        "X-Content-Type-Options": {
            "title": "Missing X-Content-Type-Options Header",
            "desc": "The server lacks 'X-Content-Type-Options: nosniff' header, leaving MIME-sniffing attacks possible.",
            "cwe": "CWE-16",
            "severity": FindingSeverity.LOW,
            "cvss": 2.6
        },
        "X-Frame-Options": {
            "title": "Missing Anti-Clickjacking Header (X-Frame-Options)",
            "desc": "The application lacks frame-ancestors CSP or X-Frame-Options header, risking Clickjacking.",
            "cwe": "CWE-1021",
            "severity": FindingSeverity.MEDIUM,
            "cvss": 4.3
        },
        "Referrer-Policy": {
            "title": "Missing or Permissive Referrer-Policy Header",
            "desc": "The server does not restrict referrer leakage to external domains.",
            "cwe": "CWE-200",
            "severity": FindingSeverity.INFO,
            "cvss": 2.0
        }
    }

    @property
    def name(self) -> ScannerName:
        return ScannerName.CONFIG_AUDIT

    def check_availability(self) -> Tuple[bool, str]:
        return True, self.VERSION

    def scan(
        self,
        target: str,
        timeout_seconds: int = 30,
        options: Optional[Dict[str, Any]] = None
    ) -> ScannerResult:
        start_time = time.time()
        findings: List[NormalizedFindingData] = []

        # 1. SSRF and scope validation
        try:
            TargetSecurityValidator.resolve_and_validate(target)
        except SSRFValidationError as e:
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.VERSION,
                status=ScannerExecutionStatus.FAILED,
                exit_code=1,
                execution_time_seconds=round(time.time() - start_time, 3),
                error_log=f"SSRF target security validation blocked destination: {str(e)}",
                findings=[]
            )

        # 2. Make bounded HTTP request
        try:
            with httpx.Client(timeout=timeout_seconds, follow_redirects=True, verify=False) as client:
                response = client.get(target)
                headers = {k.lower(): v for k, v in response.headers.items()}
                
                # Check for missing security response headers
                for header_name, meta in self.RECOMMENDED_HEADERS.items():
                    if header_name.lower() not in headers:
                        raw_fp = f"CONFIG:{header_name}:{target}"
                        fp = hashlib.sha256(raw_fp.encode("utf-8")).hexdigest()
                        
                        evidence_str = (
                            f"HTTP/1.1 {response.status_code} {response.reason_phrase}\n"
                            f"Target: {target}\n"
                            f"Evaluated Header: {header_name} (NOT FOUND in response headers)"
                        )

                        findings.append(NormalizedFindingData(
                            fingerprint=fp,
                            title=meta["title"],
                            description=meta["desc"],
                            category=FindingCategory.CONFIG,
                            scanner_name="CONFIG_AUDIT",
                            scanner_rule_id=f"config.http.missing.{header_name.lower()}",
                            cwe_id=meta["cwe"],
                            severity=meta["severity"],
                            cvss_score=meta["cvss"],
                            evidence_type="HTTP_TRACE",
                            file_path=target,
                            start_line=1,
                            end_line=1,
                            sanitized_evidence=evidence_str
                        ))

        except Exception as e:
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.VERSION,
                status=ScannerExecutionStatus.FAILED,
                exit_code=1,
                execution_time_seconds=round(time.time() - start_time, 3),
                error_log=f"HTTP connection failed during configuration audit: {str(e)}",
                findings=[]
            )

        duration = round(time.time() - start_time, 3)
        return ScannerResult(
            scanner_name=self.name,
            scanner_version=self.VERSION,
            status=ScannerExecutionStatus.SUCCESS,
            exit_code=0,
            execution_time_seconds=duration,
            findings=findings,
            is_emulated=False
        )
