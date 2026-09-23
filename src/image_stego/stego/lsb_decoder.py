"""NumPy-accelerated LSB decoder for extracting embedded data from images."""

from typing import Tuple
import numpy as np

from ..core.exceptions import CorruptedPayloadError
from ..core.models import StegoHeader
from .header import unpack_header, MIN_HEADER_SIZE


def extract_raw_bytes(image_array: np.ndarray, num_bytes: int) -> bytes:
    """
    Extract a specified number of bytes from the LSBs of an image array.
    """
    num_bits = num_bytes * 8
    if num_bits > image_array.size:
        raise CorruptedPayloadError("Requested byte extraction exceeds image capacity.")

    flat = image_array.reshape(-1)
    extracted_bits = flat[:num_bits] & 1
    packed_bytes = np.packbits(extracted_bits)
    return packed_bytes[:num_bytes].tobytes()


def extract_stego_packet(image_array: np.ndarray) -> Tuple[StegoHeader, bytes]:
    """
    Extract and parse the steganography header and encrypted payload from an image.
    
    Args:
        image_array: NumPy uint8 array of the stego image.
        
    Returns:
        Tuple of (StegoHeader, ciphertext_with_auth_tag).
        
    Raises:
        CorruptedPayloadError: If magic bytes don't match or payload is truncated.
    """
    if not isinstance(image_array, np.ndarray) or image_array.dtype != np.uint8:
        raise ValueError("Image array must be a valid numpy uint8 array.")

    max_possible_bytes = image_array.size // 8
    if max_possible_bytes < MIN_HEADER_SIZE:
        raise CorruptedPayloadError("Image is too small to contain a valid steganographic header.")

    # Read an initial buffer to unpack the header (up to 1024 bytes to accommodate long filenames)
    initial_buffer_size = min(1024, max_possible_bytes)
    initial_bytes = extract_raw_bytes(image_array, initial_buffer_size)

    header, header_offset = unpack_header(initial_bytes)

    total_packet_size = header_offset + header.payload_length
    if total_packet_size > max_possible_bytes:
        raise CorruptedPayloadError(
            f"Corrupted header: Declared total size ({total_packet_size:,} B) "
            f"exceeds image capacity ({max_possible_bytes:,} B)."
        )

    # Extract the full packet (or remaining slice)
    full_packet = extract_raw_bytes(image_array, total_packet_size)
    ciphertext_with_tag = full_packet[header_offset : header_offset + header.payload_length]

    return header, ciphertext_with_tag
