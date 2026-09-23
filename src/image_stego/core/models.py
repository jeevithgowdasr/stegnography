"""Data models and transfer objects for the steganography pipeline."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class PayloadType(Enum):
    TEXT = 0
    FILE = 1


@dataclass
class StegoHeader:
    """Represents the binary header embedded into the cover image."""
    magic: bytes
    version: int
    payload_type: PayloadType
    filename: Optional[str]
    salt: bytes
    nonce: bytes
    payload_length: int


@dataclass
class EmbeddingResult:
    """Result returned after successfully encrypting and embedding a secret."""
    cover_path: str
    output_path: str
    payload_bytes: int
    capacity_bytes: int
    capacity_used_pct: float
    is_file: bool
    filename: Optional[str] = None


@dataclass
class ExtractionResult:
    """Result returned after successfully extracting and decrypting a secret."""
    payload_type: PayloadType
    text_content: Optional[str] = None
    binary_content: Optional[bytes] = None
    filename: Optional[str] = None
    output_file_path: Optional[str] = None


@dataclass
class QualityMetrics:
    """Quality and fidelity metrics comparing original and stego images."""
    mse: float
    psnr_db: float
    max_pixel_diff: int
    total_pixels_modified: int
    total_pixels: int
    modified_percentage: float
