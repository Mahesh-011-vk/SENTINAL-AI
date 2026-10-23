import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple, List, Optional
from app.config import settings


class SSRFValidationError(Exception):
    """Raised when target URL violates SSRF boundaries or scope."""
    pass


class TargetSecurityValidator:
    """
    Validates web targets against SSRF, DNS rebinding, private network access,
    and cloud metadata endpoint exposure.
    """

    ALLOWED_SCHEMES = {"http", "https"}
    ALLOWED_PORTS = {80, 443, 8000, 8080, 8443, 3000, 5000}
    BLOCKED_HOSTNAMES = {
        "localhost",
        "metadata.google.internal",
        "instance-data",
        "169.254.169.254",
    }

    @classmethod
    def resolve_and_validate(cls, target_url: str, allowed_domains: Optional[List[str]] = None) -> Tuple[str, str]:
        """
        Validate URL scheme, port, hostname, and resolve IP addresses.
        Returns (canonical_hostname, resolved_ip).
        Raises SSRFValidationError on violation.
        """
        try:
            parsed = urlparse(target_url)
        except Exception as e:
            raise SSRFValidationError(f"Invalid URL structure: {str(e)}")

        if not parsed.scheme or parsed.scheme.lower() not in cls.ALLOWED_SCHEMES:
            raise SSRFValidationError(f"Disallowed scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")

        hostname = parsed.hostname
        if not hostname:
            raise SSRFValidationError("Target URL must specify a valid hostname.")

        hostname_lower = hostname.lower()

        # Reject explicitly blocked names
        if hostname_lower in cls.BLOCKED_HOSTNAMES:
            if not settings.ALLOW_LOCAL_TARGETS:
                raise SSRFValidationError(f"Destination '{hostname}' is a reserved internal or metadata host.")

        # Check port
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port not in cls.ALLOWED_PORTS and not settings.ALLOW_LOCAL_TARGETS:
            raise SSRFValidationError(f"Port {port} is not in the allowed security scan ports.")

        # Scope enforcement if allowed_domains specified
        if allowed_domains:
            domain_match = any(
                hostname_lower == domain.lower() or hostname_lower.endswith("." + domain.lower())
                for domain in allowed_domains
            )
            if not domain_match:
                raise SSRFValidationError(f"Hostname '{hostname}' is outside approved authorization scope.")

        # Resolve IP addresses and inspect each returned IP
        try:
            addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as e:
            raise SSRFValidationError(f"Failed to resolve DNS for host '{hostname}': {str(e)}")

        if not addr_info:
            raise SSRFValidationError(f"No IP addresses resolved for '{hostname}'.")

        # Check every resolved IP address
        primary_ip = None
        for item in addr_info:
            sockaddr = item[4]
            ip_str = sockaddr[0]
            if primary_ip is None:
                primary_ip = ip_str

            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                raise SSRFValidationError(f"Invalid IP address representation: {ip_str}")

            if settings.ALLOW_LOCAL_TARGETS:
                continue

            # Strict production checks
            if ip_obj.is_loopback:
                raise SSRFValidationError(f"Target resolves to loopback address: {ip_str}")
            if ip_obj.is_private:
                raise SSRFValidationError(f"Target resolves to private network address: {ip_str}")
            if ip_obj.is_link_local:
                raise SSRFValidationError(f"Target resolves to link-local address: {ip_str}")
            if ip_obj.is_multicast:
                raise SSRFValidationError(f"Target resolves to multicast address: {ip_str}")
            if ip_obj.is_reserved:
                raise SSRFValidationError(f"Target resolves to reserved address: {ip_str}")
            if str(ip_obj) == "169.254.169.254":
                raise SSRFValidationError("Target resolves to AWS/GCP cloud metadata IP: 169.254.169.254")

        return hostname, (primary_ip or "0.0.0.0")
