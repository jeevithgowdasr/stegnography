"""Unit and integration tests for stego.py module."""

import os
import pytest
import numpy as np
from pathlib import Path
from PIL import Image

import stego
from stego import (
    calculate_capacity,
    embed_data,
    extract_data,
    CapacityExceededError,
    UnsupportedFormatError,
    CorruptedPayloadError,
    ImageValidationError,
)
import crypto


@pytest.fixture
def sample_rgb_image(tmp_path: Path) -> Path:
    img_path = tmp_path / "sample_cover.png"
    arr = np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)
    Image.fromarray(arr, mode="RGB").save(img_path, format="PNG")
    return img_path


@pytest.fixture
def sample_rgba_image(tmp_path: Path) -> Path:
    img_path = tmp_path / "sample_cover_rgba.png"
    arr = np.random.randint(0, 256, (100, 100, 4), dtype=np.uint8)
    Image.fromarray(arr, mode="RGBA").save(img_path, format="PNG")
    return img_path


def test_calculate_capacity(sample_rgb_image: Path):
    # 100 x 100 x 3 = 30,000 bits = 3,750 bytes
    # Capacity = 3,750 - 4 = 3,746 bytes
    expected_capacity = (100 * 100 * 3) // 8 - 4
    capacity = calculate_capacity(sample_rgb_image)
    assert capacity == expected_capacity == 3746


def test_embed_and_extract_rgb_png_roundtrip(sample_rgb_image: Path, tmp_path: Path):
    secret_data = b"Antigravity Cybersecurity Core Stream #4096" * 10
    stego_path = tmp_path / "stego_output.png"

    output_result = embed_data(sample_rgb_image, secret_data, stego_path)
    assert Path(output_result).exists()

    recovered_data = extract_data(stego_path)
    assert recovered_data == secret_data


def test_embed_and_extract_rgba_png_preserves_alpha(sample_rgba_image: Path, tmp_path: Path):
    original_arr = np.array(Image.open(sample_rgba_image))
    secret_data = os.urandom(256)
    stego_path = tmp_path / "stego_rgba.png"

    embed_data(sample_rgba_image, secret_data, stego_path)
    recovered_data = extract_data(stego_path)
    assert recovered_data == secret_data

    # Verify Alpha channel was untouched
    stego_arr = np.array(Image.open(stego_path))
    assert np.array_equal(stego_arr[:, :, 3], original_arr[:, :, 3])


def test_embed_and_extract_bmp_roundtrip(tmp_path: Path):
    bmp_cover = tmp_path / "cover.bmp"
    arr = np.random.randint(0, 256, (50, 50, 3), dtype=np.uint8)
    Image.fromarray(arr, mode="RGB").save(bmp_cover, format="BMP")

    secret_data = b"BMP Lossless Carrier Verification Test"
    stego_bmp = tmp_path / "stego.bmp"

    embed_data(bmp_cover, secret_data, stego_bmp)
    extracted = extract_data(stego_bmp)
    assert extracted == secret_data


def test_capacity_exceeded_error(sample_rgb_image: Path, tmp_path: Path):
    capacity = calculate_capacity(sample_rgb_image)
    oversized = os.urandom(capacity + 1)
    stego_path = tmp_path / "overflow.png"

    with pytest.raises(CapacityExceededError) as exc_info:
        embed_data(sample_rgb_image, oversized, stego_path)

    assert exc_info.value.required_bytes == capacity + 1
    assert exc_info.value.available_bytes == capacity


def test_unsupported_format_rejection(tmp_path: Path):
    with pytest.raises(UnsupportedFormatError, match="Unsupported file extension"):
        calculate_capacity("image.jpeg")

    with pytest.raises(UnsupportedFormatError, match="Unsupported file extension"):
        embed_data("cover.png", b"data", "output.jpg")


def test_corrupted_payload_header_detection(sample_rgb_image: Path, tmp_path: Path):
    # If we attempt to extract from an unencoded cover image, the random LSBs will likely claim
    # a length exceeding the capacity or fail
    # Let's craft an image whose first 4 bytes indicate a massive length
    img = Image.open(sample_rgb_image)
    arr = np.array(img)
    # Set first 32 bits to 0xFF (very large unsigned int)
    flat = arr[:, :, :3].reshape(-1)
    flat[:32] |= 1  # 0xFFFFFFFF = 4,294,967,295 bytes
    corrupted_path = tmp_path / "corrupted.png"
    Image.fromarray(arr, mode="RGB").save(corrupted_path, format="PNG")

    with pytest.raises(CorruptedPayloadError, match="exceeds total available capacity"):
        extract_data(corrupted_path)


def test_end_to_end_crypto_and_stego_pipeline(sample_rgb_image: Path, tmp_path: Path):
    # 1. Plaintext secret message
    confidential_msg = "TOP_SECRET: Agent Antigravity active in sector 7G. Passkey: #994821."
    passphrase = "UltraSecureKeyphrase!2026"

    # 2. Encrypt with AES-256-GCM + PBKDF2 using crypto.py
    encrypted_payload = crypto.encrypt(confidential_msg, passphrase)
    serialized_stream = encrypted_payload.to_bytes()

    # 3. Embed encrypted stream into cover image
    stego_image_path = tmp_path / "operational_stego.png"
    embed_data(sample_rgb_image, serialized_stream, stego_image_path)

    # 4. Extract raw encrypted stream from stego image
    extracted_stream = extract_data(stego_image_path)
    assert extracted_stream == serialized_stream

    # 5. Decrypt recovered payload with crypto.py
    decrypted_msg = crypto.decrypt(extracted_stream, passphrase)
    assert decrypted_msg == confidential_msg

    # 6. Verify decryption fails with wrong passphrase
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(extracted_stream, "WrongPasswordAttempt")
