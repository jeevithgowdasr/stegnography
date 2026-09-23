"""Unit tests for Steganography components (Header, Capacity, LSB Encoding/Decoding)."""

import pytest
import numpy as np

from image_stego.core.models import PayloadType
from image_stego.core.exceptions import ImageCapacityExceededError, CorruptedPayloadError
from image_stego.stego.header import pack_header, unpack_header, MAGIC_BYTES
from image_stego.stego.capacity import calculate_image_capacity, calculate_max_payload_size, format_bytes
from image_stego.stego.lsb_encoder import embed_bits
from image_stego.stego.lsb_decoder import extract_stego_packet, extract_raw_bytes


def test_header_packing_text_roundtrip():
    salt = b"\x01" * 16
    nonce = b"\x02" * 12
    payload_len = 1024

    packed = pack_header(
        payload_type=PayloadType.TEXT,
        salt=salt,
        nonce=nonce,
        payload_length=payload_len,
    )

    header, offset = unpack_header(packed)

    assert header.magic == MAGIC_BYTES
    assert header.version == 1
    assert header.payload_type == PayloadType.TEXT
    assert header.filename is None
    assert header.salt == salt
    assert header.nonce == nonce
    assert header.payload_length == payload_len
    assert offset == len(packed)


def test_header_packing_file_roundtrip():
    salt = b"\x0a" * 16
    nonce = b"\x0b" * 12
    payload_len = 4096
    filename = "confidential_archive.tar.gz"

    packed = pack_header(
        payload_type=PayloadType.FILE,
        salt=salt,
        nonce=nonce,
        payload_length=payload_len,
        filename=filename,
    )

    header, offset = unpack_header(packed)

    assert header.payload_type == PayloadType.FILE
    assert header.filename == filename
    assert header.salt == salt
    assert header.nonce == nonce
    assert header.payload_length == payload_len
    assert offset == len(packed)


def test_capacity_calculations():
    w, h, c = 200, 200, 3  # 40,000 pixels * 3 = 120,000 bits = 15,000 bytes
    gross_cap = calculate_image_capacity(w, h, c)
    assert gross_cap == 15000

    max_payload = calculate_max_payload_size(w, h, c)
    assert max_payload < gross_cap
    assert max_payload > 14900

    assert format_bytes(500) == "500 B"
    assert format_bytes(2048) == "2.00 KB"
    assert format_bytes(1048576 * 3) == "3.00 MB"


def test_lsb_embed_and_extract_packet(sample_image_array):
    salt = b"\x11" * 16
    nonce = b"\x22" * 12
    ciphertext = b"EncryptedSecretDataPayloadWithAuthenticationTag1234"

    header = pack_header(
        payload_type=PayloadType.TEXT,
        salt=salt,
        nonce=nonce,
        payload_length=len(ciphertext),
    )
    full_packet = header + ciphertext

    # Embed
    stego_arr = embed_bits(sample_image_array, full_packet)

    # Verify original array unchanged
    assert not np.array_equal(sample_image_array, stego_arr)

    # Extract
    extracted_header, extracted_ciphertext = extract_stego_packet(stego_arr)

    assert extracted_header.salt == salt
    assert extracted_header.nonce == nonce
    assert extracted_ciphertext == ciphertext


def test_lsb_capacity_exceeded(sample_image_array):
    # Sample image is 100x100x3 = 30,000 bits = 3,750 bytes
    oversized_data = b"X" * 4000
    with pytest.raises(ImageCapacityExceededError):
        embed_bits(sample_image_array, oversized_data)


def test_corrupted_magic_bytes(sample_image_array):
    # Pass clean un-stegoed image to decoder
    with pytest.raises(CorruptedPayloadError, match="No steganographic data detected"):
        extract_stego_packet(sample_image_array)
