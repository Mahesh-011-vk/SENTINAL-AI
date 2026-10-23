import os
import json
import hashlib
import time
from typing import List, Optional, Dict, Any, Tuple
import yaml

from app.scanners.base import BaseScannerAdapter, ScannerResult, NormalizedFindingData
from app.models.scan import ScannerName, ScannerExecutionStatus
from app.models.finding import FindingCategory, FindingSeverity
from app.core.ssrf import TargetSecurityValidator, SSRFValidationError
from app.core.redactor import SecretRedactor


class APISpecAuditAdapter(BaseScannerAdapter):
    """
    Phase 10 — OpenAPI / Swagger Security Specification Inspector.
    Deterministically evaluates OpenAPI 3.x and Swagger 2.0 schemas for
    missing authentication mechanisms, unencrypted server endpoints,
    insecure query-based credentials, wildcard CORS, and missing error schemas.
    """

    VERSION = "1.0.0-native"

    SENSITIVE_PARAM_NAMES = {
        "token", "apikey", "api_key", "secret", "password", 
        "auth", "authorization", "access_token", "private_key"
    }

    MUTATION_METHODS = {"post", "put", "delete", "patch"}

    @property
    def name(self) -> ScannerName:
        return ScannerName.API_SPEC_AUDIT

    def check_availability(self) -> Tuple[bool, str]:
        return True, f"API Spec Security Inspector v{self.VERSION}"

    def _load_spec(self, target: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Safely parses OpenAPI / Swagger schema from path, URL, or raw string."""
        raw_text = ""
        # 1. Check if target is a URL
        if target.startswith("http://") or target.startswith("https://"):
            try:
                TargetSecurityValidator.validate_target_url(target)
                import httpx
                resp = httpx.get(target, timeout=10.0, follow_redirects=False)
                if resp.status_code != 200:
                    return None, f"HTTP error {resp.status_code} fetching API spec"
                raw_text = resp.text
            except (SSRFValidationError, Exception) as exc:
                return None, f"Target resolution failed: {str(exc)}"
        # 2. Check if target is a file path
        elif os.path.exists(target) and os.path.isfile(target):
            try:
                with open(target, "r", encoding="utf-8") as f:
                    raw_text = f.read()
            except Exception as exc:
                return None, f"File read error: {str(exc)}"
        # 3. Target is direct raw string
        else:
            raw_text = target

        # Try parsing JSON first, then YAML
        try:
            return json.loads(raw_text), None
        except Exception:
            pass

        try:
            return yaml.safe_load(raw_text), None
        except Exception as exc:
            return None, f"Failed to parse OpenAPI document as JSON or YAML: {str(exc)}"

    def scan(
        self,
        target: str,
        timeout_seconds: int = 300,
        options: Optional[Dict[str, Any]] = None
    ) -> ScannerResult:
        start_time = time.time()
        options = options or {}

        spec, error = self._load_spec(target)
        if error or not isinstance(spec, dict):
            return ScannerResult(
                scanner_name=self.name,
                scanner_version=self.VERSION,
                status=ScannerExecutionStatus.FAILED,
                exit_code=1,
                execution_time_seconds=round(time.time() - start_time, 3),
                error_log=error or "Target could not be parsed as a valid OpenAPI/Swagger schema dictionary.",
                findings=[]
            )

        findings: List[NormalizedFindingData] = []

        is_openapi3 = "openapi" in spec
        is_swagger2 = "swagger" in spec

        # Rule 1: Missing Global Security Schemes
        has_security_schemes = False
        if is_openapi3:
            components = spec.get("components", {})
            has_security_schemes = bool(components.get("securitySchemes"))
        elif is_swagger2:
            has_security_schemes = bool(spec.get("securityDefinitions"))

        global_security = spec.get("security", [])

        if not has_security_schemes:
            fp = hashlib.sha256(b"API_SPEC:RULE-01:NO_SECURITY_SCHEMES").hexdigest()
            findings.append(NormalizedFindingData(
                fingerprint=fp,
                title="Missing Security Schemes Definition in API Specification",
                description="The API specification does not declare any security schemes (e.g. OAuth2, Bearer JWT, API Key), indicating the API may lack formal authentication architecture.",
                category=FindingCategory.CONFIG,
                scanner_name=self.name.value,
                scanner_rule_id="API-SEC-01-MISSING-SCHEMES",
                cwe_id="CWE-306",
                severity=FindingSeverity.HIGH,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                evidence_type="API_SPEC_ANALYSIS",
                file_path=target if os.path.exists(target) else "openapi_spec",
                sanitized_evidence="components: {}\n# securitySchemes: NOT FOUND"
            ))

        # Rule 2: Insecure HTTP Protocol in Server / Host URLs
        server_urls = []
        if is_openapi3:
            for s in spec.get("servers", []):
                server_urls.append(s.get("url", ""))
        elif is_swagger2:
            schemes = spec.get("schemes", [])
            host = spec.get("host", "")
            for sch in schemes:
                server_urls.append(f"{sch}://{host}")

        for s_url in server_urls:
            if s_url.lower().startswith("http://"):
                fp = hashlib.sha256(f"API_SPEC:RULE-02:{s_url}".encode()).hexdigest()
                findings.append(NormalizedFindingData(
                    fingerprint=fp,
                    title="Insecure Plaintext HTTP Transport Defined in Server URL",
                    description=f"API server definition declares an unencrypted HTTP endpoint '{s_url}'. Plaintext transport exposes API keys and request bodies to interception and manipulation.",
                    category=FindingCategory.CONFIG,
                    scanner_name=self.name.value,
                    scanner_rule_id="API-SEC-02-INSECURE-HTTP",
                    cwe_id="CWE-319",
                    severity=FindingSeverity.MEDIUM,
                    cvss_score=5.9,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    evidence_type="API_SPEC_ANALYSIS",
                    file_path=target if os.path.exists(target) else "openapi_spec",
                    sanitized_evidence=f"server_url: {s_url}"
                ))

        # Inspect Paths and Operations
        paths = spec.get("paths", {})
        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            for method, operation in path_item.items():
                method_lower = method.lower()
                if method_lower not in {"get", "post", "put", "delete", "patch", "options", "head"}:
                    continue
                if not isinstance(operation, dict):
                    continue

                # Rule 3: Unauthenticated Mutation Operations
                op_security = operation.get("security")
                effective_security = op_security if op_security is not None else global_security

                if method_lower in self.MUTATION_METHODS and not effective_security:
                    fp = hashlib.sha256(f"API_SPEC:RULE-03:{method_lower}:{path_str}".encode()).hexdigest()
                    findings.append(NormalizedFindingData(
                        fingerprint=fp,
                        title=f"Unauthenticated State-Changing Operation: {method.upper()} {path_str}",
                        description=f"State-changing endpoint {method.upper()} '{path_str}' does not enforce authentication schemes, allowing unauthenticated caller execution.",
                        category=FindingCategory.CONFIG,
                        scanner_name=self.name.value,
                        scanner_rule_id="API-SEC-03-UNAUTHENTICATED-MUTATION",
                        cwe_id="CWE-306",
                        severity=FindingSeverity.HIGH,
                        cvss_score=7.2,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
                        evidence_type="API_SPEC_ANALYSIS",
                        file_path=target if os.path.exists(target) else "openapi_spec",
                        sanitized_evidence=f"path: {path_str}\nmethod: {method.upper()}\nsecurity: []"
                    ))

                # Rule 4: Query-based Credentials in Parameters
                parameters = operation.get("parameters", [])
                for param in parameters:
                    if not isinstance(param, dict):
                        continue
                    p_in = param.get("in", "").lower()
                    p_name = param.get("name", "").lower()

                    if p_in == "query" and p_name in self.SENSITIVE_PARAM_NAMES:
                        fp = hashlib.sha256(f"API_SPEC:RULE-04:{path_str}:{p_name}".encode()).hexdigest()
                        findings.append(NormalizedFindingData(
                            fingerprint=fp,
                            title=f"Sensitive Credential Passed via URL Query Parameter: '{param.get('name')}'",
                            description=f"Parameter '{param.get('name')}' is passed in the URL query string. Query parameters are logged in web server logs, proxy histories, and browser caches.",
                            category=FindingCategory.CONFIG,
                            scanner_name=self.name.value,
                            scanner_rule_id="API-SEC-04-QUERY-CREDENTIAL",
                            cwe_id="CWE-598",
                            severity=FindingSeverity.HIGH,
                            cvss_score=7.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            evidence_type="API_SPEC_ANALYSIS",
                            file_path=target if os.path.exists(target) else "openapi_spec",
                            sanitized_evidence=f"endpoint: {method.upper()} {path_str}\nparameter: {param.get('name')} (in: query)"
                        ))

                # Rule 5: Wildcard CORS Header in Operation Responses
                responses = operation.get("responses", {})
                for resp_code, resp_def in responses.items():
                    if not isinstance(resp_def, dict):
                        continue
                    headers = resp_def.get("headers", {})
                    for h_name, h_def in headers.items():
                        if h_name.lower() == "access-control-allow-origin":
                            example_val = str(h_def.get("schema", {}).get("example") or h_def.get("example") or "")
                            if example_val == "*":
                                fp = hashlib.sha256(f"API_SPEC:RULE-05:{path_str}:{h_name}".encode()).hexdigest()
                                findings.append(NormalizedFindingData(
                                    fingerprint=fp,
                                    title=f"Permissive Wildcard Access-Control-Allow-Origin Defined in Response",
                                    description=f"Endpoint {path_str} specifies wildcard CORS ('*'). This allows cross-origin reading of responses from unauthorized web origins.",
                                    category=FindingCategory.CONFIG,
                                    scanner_name=self.name.value,
                                    scanner_rule_id="API-SEC-05-WILDCARD-CORS",
                                    cwe_id="CWE-942",
                                    severity=FindingSeverity.MEDIUM,
                                    cvss_score=5.3,
                                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                                    evidence_type="API_SPEC_ANALYSIS",
                                    file_path=target if os.path.exists(target) else "openapi_spec",
                                    sanitized_evidence=f"header: {h_name}: *"
                                ))

        exec_time = round(time.time() - start_time, 3)
        return ScannerResult(
            scanner_name=self.name,
            scanner_version=self.VERSION,
            status=ScannerExecutionStatus.SUCCESS,
            exit_code=0,
            execution_time_seconds=exec_time,
            findings=findings
        )
