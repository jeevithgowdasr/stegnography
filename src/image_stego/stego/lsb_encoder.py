"""NumPy-accelerated LSB encoder for embedding bit sequences into images."""

import numpy as np
from ..core.exceptions import ImageCapacityExceededError


def embed_bits(image_array: np.ndarray, packet_bytes: bytes) -> np.ndarray:
    """
    Embed byte stream into the least significant bits of an image array.
    
    Args:
        image_array: Original image as a NumPy uint8 array (shape: (H, W, C) or (H, W)).
        packet_bytes: Serialized binary packet containing header and encrypted payload.
        
    Returns:
        New NumPy uint8 array containing the embedded secret data.
        
    Raises:
        ImageCapacityExceededError: If the packet size exceeds available LSB storage.
    """
    if not isinstance(image_array, np.ndarray) or image_array.dtype != np.uint8:
        raise ValueError("Image array must be a valid numpy uint8 array.")

    # Convert packet bytes to 1D bit array (0s and 1s)
    byte_buffer = np.frombuffer(packet_bytes, dtype=np.uint8)
    bit_array = np.unpackbits(byte_buffer)
    total_bits = len(bit_array)

    total_capacity_bits = image_array.size
    if total_bits > total_capacity_bits:
        raise ImageCapacityExceededError(
            required_bytes=len(packet_bytes),
            available_bytes=total_capacity_bits // 8,
        )

    # Flatten array to 1D view, clear LSBs for the required length, and insert secret bits
    stego_flat = image_array.reshape(-1).copy()
    stego_flat[:total_bits] = (stego_flat[:total_bits] & 0xFE) | bit_array

    # Reshape back to original dimensions
    return stego_flat.reshape(image_array.shape)
