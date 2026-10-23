import abc
from typing import List, Optional, Dict, Any, Tuple
from pydantic import BaseModel, Field
from app.models.scan import ScannerName, ScannerExecutionStatus
from app.models.finding import FindingCategory, FindingSeverity


class NormalizedFindingData(BaseModel):
    """
    Canonical normalized finding payload produced by scanner adapters
    prior to database persistence, correlation, and risk calculation.
    """
    fingerprint: str = Field(..., description="Unique composite fingerprint for deduplication")
    title: str = Field(..., max_length=512)
    description: str
    category: FindingCategory
    scanner_name: str
    scanner_rule_id: str
    cwe_id: Optional[str] = None
    severity: FindingSeverity
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    
    # Evidence location details
    evidence_type: str = "CODE_SNIPPET"
    file_path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    sanitized_evidence: str
    raw_hash: Optional[str] = None


class ScannerResult(BaseModel):
    """Execution outcome of a single security scanner tool."""
    scanner_name: ScannerName
    scanner_version: str
    status: ScannerExecutionStatus
    exit_code: int = 0
    execution_time_seconds: float = 0.0
    error_log: Optional[str] = None
    findings: List[NormalizedFindingData] = []
    is_emulated: bool = False


class BaseScannerAdapter(abc.ABC):
    """
    Abstract contract for all SentinelAI security scanner adapters.
    Enforces argument arrays without shell interpolation, timeouts,
    error handling, output bounds, and secret redaction.
    """

    @property
    @abc.abstractmethod
    def name(self) -> ScannerName:
        """Name of the security tool."""
        pass

    @abc.abstractmethod
    def check_availability(self) -> Tuple[bool, str]:
        """
        Check if scanner binary is installed and executable.
        Returns (is_available, version_string).
        """
        pass

    @abc.abstractmethod
    def scan(
        self,
        target: str,
        timeout_seconds: int = 300,
        options: Optional[Dict[str, Any]] = None
    ) -> ScannerResult:
        """
        Execute security assessment against target and return normalized results.
        Must enforce timeouts and never raise unhandled exceptions.
        """
        pass
