"""Steganography encoding, decoding, header, and capacity management."""

from .header import pack_header, unpack_header, MAGIC_BYTES, MIN_HEADER_SIZE
from .capacity import calculate_image_capacity, calculate_max_payload_size, format_bytes
from .lsb_encoder import embed_bits
from .lsb_decoder import extract_stego_packet, extract_raw_bytes

__all__ = [
    "pack_header",
    "unpack_header",
    "MAGIC_BYTES",
    "MIN_HEADER_SIZE",
    "calculate_image_capacity",
    "calculate_max_payload_size",
    "format_bytes",
    "embed_bits",
    "extract_stego_packet",
    "extract_raw_bytes",
]
