import re
import math
from typing import Tuple, List


class SecretRedactor:
    """
    Sanitizes raw text, code snippets, scanner messages, and stack traces
    to ensure zero leakage of credentials, tokens, or private keys into
    databases, logs, AI prompts, or export reports.
    """

    PATTERNS: List[Tuple[str, re.Pattern]] = [
        # Private Keys
        (
            "PRIVATE_KEY",
            re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
        ),
        # AWS Access Key ID
        (
            "AWS_ACCESS_KEY_ID",
            re.compile(r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b")
        ),
        # AWS Secret Access Key
        (
            "AWS_SECRET_KEY",
            re.compile(r"(?i)\b(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?")
        ),
        # GitHub Personal Access Tokens
        (
            "GITHUB_PAT",
            re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b")
        ),
        # Slack Tokens
        (
            "SLACK_TOKEN",
            re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b")
        ),
        # Stripe API Keys
        (
            "STRIPE_KEY",
            re.compile(r"\b(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,99}\b")
        ),
        # Bearer Tokens & JWTs
        (
            "BEARER_TOKEN",
            re.compile(r"(?i)\bBearer\s+([a-zA-Z0-9\-_=]+\.[a-zA-Z0-9\-_=]+\.[a-zA-Z0-9\-_=]+)\b")
        ),
        (
            "JWT_TOKEN",
            re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
        ),
        # Generic Secret/Password assignments
        (
            "GENERIC_SECRET",
            re.compile(r"(?i)(?:password|passwd|pwd|secret|api_key|apikey|auth_token|access_token|client_secret)\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]")
        ),
        # Database URIs with embedded passwords
        (
            "DATABASE_URI_CREDENTIALS",
            re.compile(r"(?i)([a-z0-9+]+://[^:]+:)([^@\s]+)(@[^/\s]+)")
        ),
    ]

    @classmethod
    def calculate_shannon_entropy(cls, data: str) -> float:
        """Calculate Shannon entropy for identifying high-entropy secret candidates."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def redact(cls, text: str) -> str:
        """
        Redact all detected sensitive patterns from text.
        Returns clean sanitized string.
        """
        if not text:
            return ""

        sanitized = str(text)

        # Database URI special handling to preserve host/db while masking password
        def sanitize_db_uri(match: re.Match) -> str:
            prefix = match.group(1)
            suffix = match.group(3)
            return f"{prefix}[REDACTED_PASSWORD]{suffix}"

        sanitized = re.sub(
            r"(?i)([a-z0-9+]+://[^:]+:)([^@\s]+)(@[^/\s]+)",
            sanitize_db_uri,
            sanitized
        )

        # Apply specific regex pattern redactors
        for label, pattern in cls.PATTERNS:
            if label == "DATABASE_URI_CREDENTIALS":
                continue
            
            # For capture groups, replace the secret group; otherwise replace entire match
            def make_replacer(lbl: str):
                def replace_match(m: re.Match) -> str:
                    if m.lastindex and m.lastindex >= 1:
                        # Replace the captured group
                        full = m.group(0)
                        secret = m.group(m.lastindex)
                        return full.replace(secret, f"[REDACTED_{lbl}]")
                    return f"[REDACTED_{lbl}]"
                return replace_match

            sanitized = pattern.sub(make_replacer(label), sanitized)

        return sanitized
