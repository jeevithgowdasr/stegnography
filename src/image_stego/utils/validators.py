"""Image format and integrity validators."""

import os
from pathlib import Path
from ..core.exceptions import UnsupportedFormatError, ImageValidationError

SUPPORTED_EXTENSIONS = {".png", ".bmp"}
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
BMP_SIGNATURE = b"BM"


def validate_image_path(filepath: str | Path, must_exist: bool = True) -> Path:
    """
    Validate that an image path has a supported lossless extension and exists if required.
    
    Args:
        filepath: Path to the image file.
        must_exist: Whether to verify that the file exists on disk.
        
    Returns:
        Validated Path object.
        
    Raises:
        UnsupportedFormatError: If format is lossy (e.g., JPEG, WEBP) or unsupported.
        ImageValidationError: If file does not exist or is empty.
    """
    path = Path(filepath)
    ext = path.suffix.lower()

    if ext in {".jpg", ".jpeg", ".webp"}:
        raise UnsupportedFormatError(
            f"Format '{ext}' is lossy and corrupts steganographic data. "
            f"Please use lossless formats: {', '.join(sorted(SUPPORTED_EXTENSIONS))}."
        )

    if ext not in SUPPORTED_EXTENSIONS:
        raise UnsupportedFormatError(
            f"Unsupported file format '{ext}'. "
            f"Only lossless formats ({', '.join(sorted(SUPPORTED_EXTENSIONS))}) are supported."
        )

    if must_exist:
        if not path.is_file():
            raise ImageValidationError(f"Image file not found: {path}")
        if path.stat().st_size == 0:
            raise ImageValidationError(f"Image file is empty (0 bytes): {path}")

        # Validate magic byte header
        with open(path, "rb") as f:
            header_sample = f.read(8)
            if ext == ".png" and not header_sample.startswith(PNG_SIGNATURE):
                raise ImageValidationError(f"File '{path.name}' has .png extension but is not a valid PNG file.")
            elif ext == ".bmp" and not header_sample.startswith(BMP_SIGNATURE):
                raise ImageValidationError(f"File '{path.name}' has .bmp extension but is not a valid BMP file.")

    return path


def validate_output_path(filepath: str | Path) -> Path:
    """Validate that the target output image path has a valid lossless extension."""
    return validate_image_path(filepath, must_exist=False)
