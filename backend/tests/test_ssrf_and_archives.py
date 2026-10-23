import os
import zipfile
import pytest
from app.core.ssrf import TargetSecurityValidator, SSRFValidationError
from app.core.archive_validator import ArchiveSecurityValidator, ArchiveSecurityError


def test_ssrf_blocks_localhost():
    with pytest.raises(SSRFValidationError) as exc:
        TargetSecurityValidator.resolve_and_validate("http://localhost:8080")
    assert "reserved internal or metadata host" in str(exc.value) or "loopback" in str(exc.value)


def test_ssrf_blocks_loopback_ip():
    with pytest.raises(SSRFValidationError) as exc:
        TargetSecurityValidator.resolve_and_validate("http://127.0.0.1:8000")
    assert "loopback address" in str(exc.value)


def test_ssrf_blocks_aws_metadata_ip():
    with pytest.raises(SSRFValidationError) as exc:
        TargetSecurityValidator.resolve_and_validate("http://169.254.169.254/latest/meta-data/")
    assert "reserved internal or metadata host" in str(exc.value) or "metadata IP" in str(exc.value)


def test_ssrf_blocks_disallowed_schemes():
    with pytest.raises(SSRFValidationError) as exc:
        TargetSecurityValidator.resolve_and_validate("ftp://example.com/file.txt")
    assert "Only HTTP and HTTPS are permitted" in str(exc.value)


def test_ssrf_enforces_domain_scope():
    with pytest.raises(SSRFValidationError) as exc:
        TargetSecurityValidator.resolve_and_validate(
            "https://evil.com/app",
            allowed_domains=["api.example.com", "app.example.com"]
        )
    assert "outside approved authorization scope" in str(exc.value)


def test_archive_validator_blocks_path_traversal(tmp_path):
    # Create malicious zip containing ../../etc/passwd
    malicious_zip = tmp_path / "evil.zip"
    with zipfile.ZipFile(malicious_zip, "w") as zf:
        zf.writestr("../../etc/evil.txt", "malicious payload")

    target_dir = tmp_path / "extracted"

    with pytest.raises(ArchiveSecurityError) as exc:
        ArchiveSecurityValidator.validate_and_extract_zip(str(malicious_zip), str(target_dir))
    assert "Directory traversal detected" in str(exc.value)


def test_archive_validator_extracts_safe_zip(tmp_path):
    safe_zip = tmp_path / "safe.zip"
    with zipfile.ZipFile(safe_zip, "w") as zf:
        zf.writestr("src/main.py", "print('hello world')\n")
        zf.writestr("README.md", "# Safe Project\n")

    target_dir = tmp_path / "extracted_safe"
    extracted = ArchiveSecurityValidator.validate_and_extract_zip(str(safe_zip), str(target_dir))

    assert len(extracted) == 2
    assert os.path.exists(target_dir / "src" / "main.py")
    assert os.path.exists(target_dir / "README.md")
