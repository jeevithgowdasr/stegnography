"""Integration tests for end-to-end encryption & steganography pipelines."""

import pytest
from pathlib import Path

from image_stego.core.pipeline import encrypt_and_hide, extract_and_decrypt
from image_stego.core.models import PayloadType
from image_stego.core.exceptions import DecryptionError, ImageCapacityExceededError, UnsupportedFormatError


def test_end_to_end_text_png(sample_png_file, tmp_path):
    secret_text = "Mission Launch Coordinates: 48.8584° N, 2.2945° E. Alpha-Bravo."
    password = "MyComplexPassword@2026!"
    out_stego_png = tmp_path / "result_stego.png"

    # 1. Encrypt and hide
    embed_res = encrypt_and_hide(
        cover_image_path=sample_png_file,
        password=password,
        secret_text=secret_text,
        output_image_path=out_stego_png,
    )

    assert Path(embed_res.output_path).is_file()
    assert embed_res.payload_bytes == len(secret_text.encode("utf-8"))
    assert embed_res.capacity_used_pct > 0

    # 2. Extract and decrypt
    extract_res = extract_and_decrypt(
        stego_image_path=out_stego_png,
        password=password,
    )

    assert extract_res.payload_type == PayloadType.TEXT
    assert extract_res.text_content == secret_text


def test_end_to_end_text_bmp(sample_bmp_file, tmp_path):
    secret_text = "BMP Lossless Stego Verification Test Payload."
    password = "BmpPasscode#991"
    out_stego_bmp = tmp_path / "result_stego.bmp"

    # 1. Encrypt and hide
    embed_res = encrypt_and_hide(
        cover_image_path=sample_bmp_file,
        password=password,
        secret_text=secret_text,
        output_image_path=out_stego_bmp,
    )

    assert Path(embed_res.output_path).is_file()

    # 2. Extract and decrypt
    extract_res = extract_and_decrypt(
        stego_image_path=out_stego_bmp,
        password=password,
    )

    assert extract_res.payload_type == PayloadType.TEXT
    assert extract_res.text_content == secret_text


def test_end_to_end_file_payload(sample_png_file, sample_secret_file, tmp_path):
    password = "FileSecretKey!42"
    out_stego_png = tmp_path / "file_stego.png"
    extract_out_dir = tmp_path / "extracted_folder"

    # 1. Encrypt and hide secret file
    embed_res = encrypt_and_hide(
        cover_image_path=sample_png_file,
        password=password,
        secret_file_path=sample_secret_file,
        output_image_path=out_stego_png,
    )

    assert embed_res.is_file is True
    assert embed_res.filename == sample_secret_file.name

    # 2. Extract and decrypt secret file
    extract_res = extract_and_decrypt(
        stego_image_path=out_stego_png,
        password=password,
        output_directory=extract_out_dir,
    )

    assert extract_res.payload_type == PayloadType.FILE
    assert extract_res.filename == sample_secret_file.name
    assert extract_res.output_file_path is not None
    assert Path(extract_res.output_file_path).is_file()

    # Verify extracted binary content is identical bit-for-bit
    original_bytes = sample_secret_file.read_bytes()
    extracted_bytes = Path(extract_res.output_file_path).read_bytes()
    assert original_bytes == extracted_bytes


def test_pipeline_wrong_password_fails(sample_png_file, tmp_path):
    secret_text = "Authentic secret message."
    correct_password = "CorrectKey123"
    wrong_password = "WrongPassword456"
    out_stego_png = tmp_path / "pwd_test.png"

    encrypt_and_hide(
        cover_image_path=sample_png_file,
        password=correct_password,
        secret_text=secret_text,
        output_image_path=out_stego_png,
    )

    with pytest.raises(DecryptionError, match="Authentication failed"):
        extract_and_decrypt(
            stego_image_path=out_stego_png,
            password=wrong_password,
        )


def test_lossy_format_rejection(tmp_path):
    fake_jpg = tmp_path / "test.jpg"
    fake_jpg.write_text("dummy")

    with pytest.raises(UnsupportedFormatError, match="lossy and corrupts"):
        encrypt_and_hide(
            cover_image_path=fake_jpg,
            password="pass",
            secret_text="msg",
        )
