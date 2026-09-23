"""Image capacity calculations and formatting utilities."""

from typing import Optional
from .header import MIN_HEADER_SIZE
from ..crypto.encryptor import TAG_LENGTH


def calculate_image_capacity(width: int, height: int, channels: int = 3) -> int:
    """
    Calculate the total gross byte capacity of an image for 1-bit-per-channel LSB embedding.
    
    Args:
        width: Image width in pixels.
        height: Image height in pixels.
        channels: Color channels (typically 3 for RGB, 4 for RGBA, 1 for Grayscale).
        
    Returns:
        Total bytes that can be stored in the image LSBs.
    """
    total_bits = width * height * channels
    return total_bits // 8


def calculate_max_payload_size(
    width: int,
    height: int,
    channels: int = 3,
    filename: Optional[str] = None,
) -> int:
    """
    Calculate the maximum plaintext payload size (in bytes) that can fit in the image,
    accounting for header overhead and cryptographic authentication tags.
    """
    gross_capacity = calculate_image_capacity(width, height, channels)
    filename_overhead = len(filename.encode("utf-8")) if filename else 0
    total_overhead = MIN_HEADER_SIZE + filename_overhead + TAG_LENGTH
    return max(0, gross_capacity - total_overhead)


def format_bytes(num_bytes: int) -> str:
    """Format an integer byte count into a human-readable string (B, KB, MB, GB)."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.2f} KB"
    elif num_bytes < 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{num_bytes / (1024 * 1024 * 1024):.2f} GB"
