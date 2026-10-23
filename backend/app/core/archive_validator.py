import os
import zipfile
import tarfile
from pathlib import Path
from typing import List
from app.config import settings


class ArchiveSecurityError(Exception):
    """Raised when source archive violates path traversal, symlink, or resource limits."""
    pass


class ArchiveSecurityValidator:
    """
    Safely inspects and extracts untrusted source code archives, preventing
    Zip Slip, directory traversal, symlink escapes, and zip bomb resource exhaustion.
    """

    @classmethod
    def validate_and_extract_zip(cls, archive_path: str, extract_to: str) -> List[str]:
        """
        Safely validate and extract a zip file to the target directory.
        Returns a list of extracted file paths.
        """
        extract_dir = Path(extract_to).resolve()
        os.makedirs(extract_dir, exist_ok=True)

        if not os.path.exists(archive_path):
            raise ArchiveSecurityError(f"Archive file not found: {archive_path}")

        extracted_files: List[str] = []
        total_uncompressed_bytes = 0
        total_files = 0

        try:
            with zipfile.ZipFile(archive_path, 'r') as zf:
                for member in zf.infolist():
                    total_files += 1
                    if total_files > settings.MAX_ARCHIVE_FILES:
                        raise ArchiveSecurityError(
                            f"Archive file count exceeded safe limit ({settings.MAX_ARCHIVE_FILES} files)."
                        )

                    total_uncompressed_bytes += member.file_size
                    if total_uncompressed_bytes > settings.MAX_ARCHIVE_SIZE_BYTES:
                        raise ArchiveSecurityError(
                            f"Archive uncompressed size exceeded safe limit ({settings.MAX_ARCHIVE_SIZE_BYTES} bytes)."
                        )

                    # Directory traversal check
                    filename = member.filename
                    if ".." in filename or filename.startswith("/") or filename.startswith("\\"):
                        raise ArchiveSecurityError(f"Directory traversal detected in archive entry: {filename}")

                    # Resolve destination path
                    target_path = (extract_dir / filename).resolve()
                    if not str(target_path).startswith(str(extract_dir)):
                        raise ArchiveSecurityError(f"Entry resolves outside target extraction directory: {filename}")

                    # Extract file safely
                    if member.is_dir():
                        os.makedirs(target_path, exist_ok=True)
                    else:
                        os.makedirs(target_path.parent, exist_ok=True)
                        with zf.open(member) as source, open(target_path, "wb") as target:
                            target.write(source.read())
                        extracted_files.append(str(target_path))

        except zipfile.BadZipFile as e:
            raise ArchiveSecurityError(f"Corrupted or invalid zip file: {str(e)}")

        return extracted_files
