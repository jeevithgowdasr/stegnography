"""Unit tests for pipeline.py module."""

import numpy as np
import pytest
from pathlib import Path
from PIL import Image

import pipeline
from pipeline import (
    encrypt_and_hide,
    extract_and_decrypt,
    PipelineError,
    CapacityError,
    AuthenticationError,
    UnsupportedFormatError,
)


@pytest.fixture
def cover_image(tmp_path: Path) -> Path:
    img_path = tmp_path / "test_cover.png"
    arr = np.random.randint(0, 256, (120, 120, 3), dtype=np.uint8)
    Image.fromarray(arr, mode="RGB").save(img_path, format="PNG")
    return img_path


def test_pipeline_encrypt_hide_extract_decrypt_roundtrip(cover_image: Path, tmp_path: Path):
    secret_text = "Mission Directive: Antigravity Steganography Engine 2026."
    password = "MasterPassword#9911"
    stego_path = tmp_path / "output_stego.png"

    result = encrypt_and_hide(
        cover_image_path=cover_image,
        secret_text=secret_text,
        passphrase=password,
        output_image_path=stego_path,
    )

    assert result["success"] is True
    assert result["psnr_db"] > 40.0
    assert result["is_imperceptible"] is True
    assert Path(result["output_path"]).is_file()

    recovered_text = extract_and_decrypt(
        stego_image_path=stego_path,
        passphrase=password,
    )

    assert recovered_text == secret_text


def test_pipeline_wrong_password_raises_authentication_error(cover_image: Path, tmp_path: Path):
    secret_text = "Highly classified operational details."
    password = "CorrectSecretPassword"
    wrong_password = "WrongPasswordGuess"
    stego_path = tmp_path / "output_stego.png"

    encrypt_and_hide(cover_image, secret_text, password, stego_path)

    with pytest.raises(AuthenticationError, match="Authentication failed|Incorrect password"):
        extract_and_decrypt(stego_path, wrong_password)


def test_pipeline_capacity_overflow_raises_capacity_error(cover_image: Path, tmp_path: Path):
    # Cover image is 120x120 -> capacity is (120*120*3)//8 - 4 = 5,396 bytes
    oversized_text = "X" * 6000
    password = "SecretPassword"
    stego_path = tmp_path / "overflow.png"

    with pytest.raises(CapacityError, match="Insufficient carrier capacity"):
        encrypt_and_hide(cover_image, oversized_text, password, stego_path)


def test_pipeline_lossy_format_raises_unsupported_format(tmp_path: Path):
    with pytest.raises(UnsupportedFormatError, match="Cover image format error"):
        encrypt_and_hide("photo.jpg", "secret", "password", tmp_path / "out.png")

    with pytest.raises(UnsupportedFormatError, match="Stego image format error"):
        extract_and_decrypt("photo.jpg", "password")
