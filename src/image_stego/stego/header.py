"""Binary header specification and packing/unpacking for stego payloads."""

import struct
from typing import Optional, Tuple
from ..core.exceptions import CorruptedPayloadError
from ..core.models import PayloadType, StegoHeader

MAGIC_BYTES = b"STEG"
PROTOCOL_VERSION = 1
MIN_HEADER_SIZE = 40  # 4(magic) + 1(ver) + 1(type) + 2(name_len) + 16(salt) + 12(nonce) + 4(payload_len)


def pack_header(
    payload_type: PayloadType,
    salt: bytes,
    nonce: bytes,
    payload_length: int,
    filename: Optional[str] = None,
) -> bytes:
    """
    Serialize steganography metadata into a binary header.
    
    Structure:
    - Magic (4B): b"STEG"
    - Version (1B): 0x01
    - Type (1B): 0x00 (Text) or 0x01 (File)
    - Filename length (2B): uint16
    - Filename bytes: UTF-8 encoded string
    - Salt (16B): KDF salt
    - Nonce (12B): GCM nonce
    - Payload length (4B): uint32 (size of ciphertext + tag)
    """
    if len(salt) != 16:
        raise ValueError("Salt must be exactly 16 bytes.")
    if len(nonce) != 12:
        raise ValueError("Nonce must be exactly 12 bytes.")

    filename_bytes = filename.encode("utf-8") if (filename and payload_type == PayloadType.FILE) else b""
    filename_len = len(filename_bytes)

    header_prefix = struct.pack(
        ">4sBBH",
        MAGIC_BYTES,
        PROTOCOL_VERSION,
        payload_type.value,
        filename_len,
    )

    header_suffix = struct.pack(">16s12sI", salt, nonce, payload_length)

    return header_prefix + filename_bytes + header_suffix


def unpack_header(data: bytes) -> Tuple[StegoHeader, int]:
    """
    Parse the binary header from extracted raw bytes.
    
    Returns:
        Tuple of (StegoHeader, total_header_bytes_consumed).
        
    Raises:
        CorruptedPayloadError: If magic bytes do not match or header is malformed.
    """
    if len(data) < 8:
        raise CorruptedPayloadError("Data is too short to contain a valid steganography header.")

    magic, version, p_type_val, filename_len = struct.unpack_from(">4sBBH", data, 0)
    if magic != MAGIC_BYTES:
        raise CorruptedPayloadError(
            "No steganographic data detected: Magic signature mismatch. "
            "Ensure the image contains an embedded payload."
        )

    if version != PROTOCOL_VERSION:
        raise CorruptedPayloadError(f"Unsupported stego protocol version: {version}")

    try:
        payload_type = PayloadType(p_type_val)
    except ValueError:
        raise CorruptedPayloadError(f"Invalid payload type identifier: {p_type_val}")

    offset = 8
    filename = None
    if filename_len > 0:
        if len(data) < offset + filename_len:
            raise CorruptedPayloadError("Truncated header: incomplete filename.")
        filename = data[offset : offset + filename_len].decode("utf-8", errors="replace")
        offset += filename_len

    suffix_size = struct.calcsize(">16s12sI")
    if len(data) < offset + suffix_size:
        raise CorruptedPayloadError("Truncated header: missing cryptographic parameters.")

    salt, nonce, payload_len = struct.unpack_from(">16s12sI", data, offset)
    offset += suffix_size

    header = StegoHeader(
        magic=magic,
        version=version,
        payload_type=payload_type,
        filename=filename,
        salt=salt,
        nonce=nonce,
        payload_length=payload_len,
    )
    return header, offset
