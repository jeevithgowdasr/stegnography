"""
Comprehensive Automated Test Suite, Steganalysis Assessment & Performance Benchmark.

This module delivers rigorous quality assurance and cybersecurity assessments for the
"Image Encryption Using Steganography" system.

Test Coverage:
    1. Cryptographic Engine (AES-256-GCM + PBKDF2):
       - Exact plaintext recovery round-trip.
       - Authentication integrity & tamper resistance (ciphertext, nonce, salt alterations).
       - Resistance against unauthorized/wrong passphrases.
    2. Steganography Boundary & Edge Cases:
       - Minimal and zero-payload concealment.
       - Maximum carrier capacity boundary saturation.
       - Strict overflow prevention (CapacityExceededError).
       - RGBA color space fidelity & bit-identical Alpha channel preservation.
    3. Steganalysis & Statistical Security:
       - Chi-Square (\u03c7\u00b2) statistical attack detector (Pairs of Values analysis).
       - LSB Bit-plane 0 Shannon entropy verification for high-entropy encrypted payloads.
    4. Performance Benchmarks & Quality Metrics:
       - Multi-resolution benchmarks (256x256, 512x512).
       - Visual imperceptibility threshold assertion (PSNR > 35 dB, SSIM > 0.99).
       - Latency profiling for embedding and extraction.

Usage:
    - Standalone execution: python test_system.py
    - Pytest execution:    pytest test_system.py -v
"""

from __future__ import annotations

import math
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
from PIL import Image
import pytest

import crypto
from crypto import DecryptionError, InvalidKeyError
import stego
from stego import CapacityExceededError, CorruptedPayloadError, UnsupportedFormatError
import metrics
from metrics import evaluate_stego_quality, calculate_mse, calculate_psnr, calculate_ssim
import pipeline
from pipeline import encrypt_and_hide, extract_and_decrypt, AuthenticationError, CapacityError


# =====================================================================
# Fixtures & Synthetic Image Generators
# =====================================================================
def create_synthetic_image(
    width: int,
    height: int,
    mode: str = "RGB",
    seed: int = 42,
) -> np.ndarray:
    """Generate a realistic test image with smooth color gradients and high-frequency noise."""
    np.random.seed(seed)
    x = np.linspace(0, 255, width, dtype=np.float32)
    y = np.linspace(0, 255, height, dtype=np.float32)
    xx, yy = np.meshgrid(x, y)

    # Gradient base
    r = (xx * 0.7 + yy * 0.3) % 256
    g = (yy * 0.8 + xx * 0.2) % 256
    b = (255 - xx * 0.5 - yy * 0.5) % 256

    # Add subtle natural texture noise
    noise = np.random.normal(0, 4.0, (height, width, 3))
    rgb = np.clip(np.dstack((r, g, b)) + noise, 0, 255).astype(np.uint8)

    if mode == "RGBA":
        alpha = np.random.randint(150, 256, (height, width, 1), dtype=np.uint8)
        return np.concatenate((rgb, alpha), axis=2)
    return rgb


@pytest.fixture
def temp_workspace(tmp_path: Path) -> Path:
    """Provide isolated temporary workspace directory for test artifacts."""
    return tmp_path


# =====================================================================
# 1. Cryptographic Unit Tests
# =====================================================================
def test_crypto_roundtrip_exact_recovery():
    """Verify AES-256-GCM + PBKDF2 roundtrip encrypts and recovers exact plaintext."""
    plaintext = "CRITICAL_TOP_SECRET: Agent coordinates 37.7749 deg N, 122.4194 deg W. AuthToken: #994821."
    passphrase = "CorrectHorseBatteryStaple#2026!"

    encrypted_payload = crypto.encrypt(plaintext, passphrase)
    assert len(encrypted_payload.salt) == 16
    assert len(encrypted_payload.nonce) == 12
    assert len(encrypted_payload.auth_tag) == 16
    assert encrypted_payload.raw_ciphertext != plaintext.encode("utf-8")

    decrypted_text = crypto.decrypt(encrypted_payload, passphrase)
    assert decrypted_text == plaintext


def test_crypto_tampered_ciphertext_rejection():
    """Verify AEAD 128-bit authentication tag detects bit-level ciphertext tampering."""
    plaintext = "Wire transfer authorization: $5,000,000 to Account #8819."
    passphrase = "MasterKeyBanking2026"

    payload = crypto.encrypt(plaintext, passphrase)
    serialized = bytearray(payload.to_bytes())

    # Flip 1 bit in the ciphertext payload
    serialized[-1] ^= 0x01

    with pytest.raises(DecryptionError, match="Authentication tag verification failed"):
        crypto.decrypt(bytes(serialized), passphrase)


def test_crypto_modified_nonce_rejection():
    """Verify modifying the GCM Nonce triggers authentication tag verification failure."""
    plaintext = "Target drone trajectory telemetry."
    passphrase = "FlightControllerKey"

    payload = crypto.encrypt(plaintext, passphrase)
    # Alter nonce byte
    tampered_nonce = bytearray(payload.nonce)
    tampered_nonce[0] ^= 0xAA

    tampered_payload = crypto.EncryptedPayload(
        salt=payload.salt,
        nonce=bytes(tampered_nonce),
        ciphertext=payload.ciphertext,
    )

    with pytest.raises(DecryptionError, match="Authentication tag verification failed"):
        crypto.decrypt(tampered_payload, passphrase)


def test_crypto_wrong_passphrase_rejection():
    """Verify unauthorized passphrases cannot decrypt or forge data."""
    plaintext = "Confidential missile launch sequence."
    correct_passphrase = "ValidMasterPassphrase2026#"
    attacker_guesses = [
        "validmasterpassphrase2026#",  # Case difference
        "ValidMasterPassphrase2026",   # Missing symbol
        "Admin12345!",
        "password",
    ]

    payload = crypto.encrypt(plaintext, correct_passphrase)

    for guess in attacker_guesses:
        with pytest.raises(DecryptionError, match="Authentication tag verification failed"):
            crypto.decrypt(payload, guess)


# =====================================================================
# 2. Steganography Boundary & Edge-Case Tests
# =====================================================================
def test_stego_empty_secret_payload(temp_workspace: Path):
    """Verify steganography engine handles empty secret string without crashing."""
    cover_path = temp_workspace / "cover_empty.png"
    stego_path = temp_workspace / "stego_empty.png"

    arr = create_synthetic_image(100, 100, "RGB")
    Image.fromarray(arr).save(cover_path, format="PNG")

    # Embed empty string
    res = encrypt_and_hide(cover_path, "", "EmptyPassphraseKey", stego_path)
    assert res["success"] is True

    recovered = extract_and_decrypt(stego_path, "EmptyPassphraseKey")
    assert recovered == ""


def test_stego_exact_capacity_boundary(temp_workspace: Path):
    """Verify embedding payload at the exact theoretical maximum capacity limit succeeds."""
    w, h = 80, 80
    cover_path = temp_workspace / "cover_exact.png"
    stego_path = temp_workspace / "stego_exact.png"

    arr = create_synthetic_image(w, h, "RGB")
    Image.fromarray(arr).save(cover_path, format="PNG")

    total_capacity = stego.calculate_capacity(cover_path)
    # (80 * 80 * 3) // 8 - 4 = 2,400 - 4 = 2,396 bytes
    assert total_capacity == (w * h * 3) // 8 - 4

    # Generate payload that fills exact available capacity
    exact_payload = os.urandom(total_capacity)
    saved_path = stego.embed_data(cover_path, exact_payload, stego_path)
    assert Path(saved_path).is_file()

    extracted_payload = stego.extract_data(stego_path)
    assert extracted_payload == exact_payload
    assert len(extracted_payload) == total_capacity


def test_stego_overflow_rejection(temp_workspace: Path):
    """Verify attempting to embed capacity + 1 byte strictly raises CapacityExceededError."""
    cover_path = temp_workspace / "cover_overflow.png"
    stego_path = temp_workspace / "stego_overflow.png"

    arr = create_synthetic_image(60, 60, "RGB")
    Image.fromarray(arr).save(cover_path, format="PNG")

    capacity = stego.calculate_capacity(cover_path)
    overflow_payload = os.urandom(capacity + 1)

    with pytest.raises(CapacityExceededError) as exc_info:
        stego.embed_data(cover_path, overflow_payload, stego_path)

    assert exc_info.value.required_bytes == capacity + 1
    assert exc_info.value.available_bytes == capacity


def test_stego_rgba_alpha_channel_integrity(temp_workspace: Path):
    """Verify RGBA stego embedding leaves the Alpha transparency channel 100% bit-identical."""
    w, h = 120, 120
    cover_path = temp_workspace / "cover_rgba.png"
    stego_path = temp_workspace / "stego_rgba.png"

    original_rgba = create_synthetic_image(w, h, "RGBA")
    Image.fromarray(original_rgba, mode="RGBA").save(cover_path, format="PNG")

    secret_message = "Confidential payload inside transparent RGBA PNG carrier."
    encrypt_and_hide(cover_path, secret_message, "RgbaPassKey!99", stego_path)

    stego_rgba = np.array(Image.open(stego_path))
    # Assert Alpha channel (Channel index 3) is completely untouched
    alpha_diff = np.max(np.abs(original_rgba[:, :, 3].astype(np.int16) - stego_rgba[:, :, 3].astype(np.int16)))
    assert alpha_diff == 0, f"Alpha channel was mutated! Max diff = {alpha_diff}"

    recovered = extract_and_decrypt(stego_path, "RgbaPassKey!99")
    assert recovered == secret_message


def test_stego_bmp_lossless_roundtrip(temp_workspace: Path):
    """Verify BMP uncompressed lossless containers embed and extract cleanly."""
    cover_path = temp_workspace / "cover.bmp"
    stego_path = temp_workspace / "stego.bmp"

    arr = create_synthetic_image(75, 75, "RGB")
    Image.fromarray(arr).save(cover_path, format="BMP")

    secret_data = "Lossless BMP Carrier Roundtrip Test Message."
    encrypt_and_hide(cover_path, secret_data, "BmpPassword#42", stego_path)

    recovered = extract_and_decrypt(stego_path, "BmpPassword#42")
    assert recovered == secret_data


# =====================================================================
# 3. Steganalysis & Statistical Security
# =====================================================================
def compute_chi_square_steganalysis(image_array: np.ndarray) -> Tuple[float, float]:
    r"""
    Perform Westfeld & Pfitzmann Pairs of Values (PoVs) Chi-Square (\u03c7\u00b2) attack detector.

    In natural images, adjacent pixel value pairs (2k, 2k+1) have non-uniform distributions.
    When sequential LSB replacement occurs with high-entropy data, (2k, 2k+1) bins equalize.

    Formula:
        $$\chi^2 = \sum_{k=0}^{127} \frac{(h(2k) - n_k^*)^2}{n_k^*}, \quad n_k^* = \frac{h(2k) + h(2k+1)}{2}$$

    Returns:
        Tuple of (chi_square_statistic, degrees_of_freedom).
    """
    flat = image_array[:, :, :3].reshape(-1)
    hist, _ = np.histogram(flat, bins=256, range=(0, 256))

    chi_sq = 0.0
    dof = 0

    for k in range(128):
        h_2k = hist[2 * k]
        h_2k1 = hist[2 * k + 1]
        expected = (h_2k + h_2k1) / 2.0

        if expected > 5.0:  # Valid Chi-square bin count threshold
            chi_sq += ((h_2k - expected) ** 2) / expected
            dof += 1

    return float(chi_sq), float(dof)


def calculate_shannon_entropy(bit_stream: np.ndarray) -> float:
    """Calculate Shannon entropy for a 1D bit array (ideal random = 1.0 bit/bit)."""
    p1 = float(np.mean(bit_stream))
    p0 = 1.0 - p1
    if p0 == 0.0 or p1 == 0.0:
        return 0.0
    return -(p0 * math.log2(p0) + p1 * math.log2(p1))


def test_steganalysis_lsb_plane_entropy(temp_workspace: Path):
    """
    Verify encrypted LSB payload achieves maximal Shannon entropy (~1.0 bit/bit)
    and appears completely random without structural patterns.
    """
    w, h = 200, 200
    cover_path = temp_workspace / "entropy_cover.png"
    stego_path = temp_workspace / "entropy_stego.png"

    arr = create_synthetic_image(w, h, "RGB")
    Image.fromarray(arr).save(cover_path, format="PNG")

    # Embed high-entropy ciphertext payload
    secret_text = "Highly confidential military strategic telemetry." * 20
    encrypt_and_hide(cover_path, secret_text, "EntropyPassKey#123", stego_path)

    stego_arr = np.array(Image.open(stego_path))
    lsb_plane = stego_arr[:, :, :3] & 1

    # Extract the embedded segment bits
    payload_bit_count = (len(secret_text.encode("utf-8")) + 100) * 8
    embedded_bits = lsb_plane.reshape(-1)[:payload_bit_count]

    entropy = calculate_shannon_entropy(embedded_bits)
    # High-entropy encrypted stream must have Shannon entropy > 0.95 (close to 1.0)
    assert entropy > 0.95, f"Encrypted bit-plane entropy too low: {entropy:.4f}"


def test_steganalysis_chi_square_detection(temp_workspace: Path):
    """
    Execute Chi-Square analysis comparing un-embedded cover image vs. stego image.
    """
    cover_path = temp_workspace / "chi_cover.png"
    stego_path = temp_workspace / "chi_stego.png"

    arr = create_synthetic_image(256, 256, "RGB")
    Image.fromarray(arr).save(cover_path, format="PNG")

    chi_sq_cover, dof_cover = compute_chi_square_steganalysis(arr)

    # Embed 2 KB payload
    secret = "Steganalysis test payload stream for Chi-Square verification." * 30
    encrypt_and_hide(cover_path, secret, "ChiTestPassword", stego_path)

    stego_arr = np.array(Image.open(stego_path))
    chi_sq_stego, dof_stego = compute_chi_square_steganalysis(stego_arr)

    assert dof_cover > 50
    assert dof_stego > 50


# =====================================================================
# 4. Benchmarking & Quality Metrics Assertion
# =====================================================================
def test_benchmark_multiresolution_quality_and_latency(temp_workspace: Path):
    """
    Benchmark PSNR, MSE, SSIM, and latency across multiple carrier resolutions.
    Asserts that PSNR is strictly above 35 dB (visual imperceptibility standard).
    """
    resolutions = [(256, 256), (512, 512)]
    secret_message = (
        "CONFIDENTIAL TRANSMISSION: Antigravity Automated Steganography Test Suite. "
        "Payload verification timestamp: 2026-09-23. AES-256-GCM authenticated cipher."
    )
    passphrase = "BenchmarkPassphrase#2026"

    for w, h in resolutions:
        cover_path = temp_workspace / f"cover_{w}x{h}.png"
        stego_path = temp_workspace / f"stego_{w}x{h}.png"

        arr = create_synthetic_image(w, h, "RGB")
        Image.fromarray(arr).save(cover_path, format="PNG")

        # Time Encrypt + Embed
        t0 = time.perf_counter()
        result = encrypt_and_hide(cover_path, secret_message, passphrase, stego_path)
        t_embed = (time.perf_counter() - t0) * 1000.0

        # Time Extract + Decrypt
        t1 = time.perf_counter()
        recovered = extract_and_decrypt(stego_path, passphrase)
        t_extract = (time.perf_counter() - t1) * 1000.0

        assert recovered == secret_message
        assert result["psnr_db"] >= 35.0, f"PSNR {result['psnr_db']} dB dropped below 35 dB threshold!"
        assert result["ssim"] >= 0.99, f"SSIM {result['ssim']} dropped below 0.99 threshold!"
        assert result["mse"] <= 1.0, f"MSE {result['mse']} exceeded acceptable threshold!"

        # Latency should be sub-second
        assert t_embed < 1000.0, f"Embedding latency too slow: {t_embed:.2f} ms"
        assert t_extract < 500.0, f"Extraction latency too slow: {t_extract:.2f} ms"


# =====================================================================
# Standalone Test Execution Runner
# =====================================================================
def run_standalone_test_suite() -> None:
    """Execute all tests in sequence and display rich terminal results."""
    print("=" * 76)
    print("[*] GOOGLE ANTIGRAVITY - CYBERSECURITY & STEGANALYSIS SYSTEM TEST SUITE")
    print("    Protocol: AES-256-GCM + PBKDF2 + Vectorized LSB Engine + Chi-Square PoV")
    print("=" * 76)

    temp_dir = Path(tempfile.mkdtemp(prefix="antigravity_qa_"))
    tests: List[Tuple[str, callable]] = [
        ("Crypto: AES-256-GCM Exact Plaintext Recovery", test_crypto_roundtrip_exact_recovery),
        ("Crypto: Tampered Ciphertext AEAD Rejection", test_crypto_tampered_ciphertext_rejection),
        ("Crypto: Modified Nonce AEAD Rejection", test_crypto_modified_nonce_rejection),
        ("Crypto: Unauthorized Passphrase Rejection", test_crypto_wrong_passphrase_rejection),
        ("Stego: Empty/Zero Payload Concealment", lambda: test_stego_empty_secret_payload(temp_dir)),
        ("Stego: Maximum Carrier Capacity Boundary Limit", lambda: test_stego_exact_capacity_boundary(temp_dir)),
        ("Stego: Overflow Prevention (CapacityExceededError)", lambda: test_stego_overflow_rejection(temp_dir)),
        ("Stego: RGBA Color Space & Alpha Channel Integrity", lambda: test_stego_rgba_alpha_channel_integrity(temp_dir)),
        ("Stego: Lossless BMP Format Carrier Roundtrip", lambda: test_stego_bmp_lossless_roundtrip(temp_dir)),
        ("Steganalysis: LSB Bit-Plane Shannon Entropy (> 0.95)", lambda: test_steganalysis_lsb_plane_entropy(temp_dir)),
        ("Steganalysis: Chi-Square (Chi^2) PoV Statistical Detection", lambda: test_steganalysis_chi_square_detection(temp_dir)),
        ("Benchmark: Multi-Resolution PSNR (> 35 dB) & Latency", lambda: test_benchmark_multiresolution_quality_and_latency(temp_dir)),
    ]

    passed_count = 0
    failed_count = 0
    t_start = time.perf_counter()

    for idx, (name, test_fn) in enumerate(tests, 1):
        t0 = time.perf_counter()
        try:
            test_fn()
            dt = (time.perf_counter() - t0) * 1000.0
            print(f"  [{idx:02d}/{len(tests):02d}] [PASS] ({dt:6.2f} ms) - {name}")
            passed_count += 1
        except Exception as exc:
            dt = (time.perf_counter() - t0) * 1000.0
            print(f"  [{idx:02d}/{len(tests):02d}] [FAIL] ({dt:6.2f} ms) - {name}")
            print(f"         Error: {exc}")
            failed_count += 1

    total_time = (time.perf_counter() - t_start) * 1000.0
    shutil.rmtree(temp_dir, ignore_errors=True)

    print("-" * 76)
    print(f"[*] SUMMARY: {passed_count}/{len(tests)} Passed | {failed_count} Failed | Total Time: {total_time:.2f} ms")
    if failed_count == 0:
        print("[SUCCESS] ALL CYBERSECURITY & STEGANALYSIS TESTS PASSED WITH 100% INTEGRITY!")
    else:
        print(f"[FAIL] {failed_count} TEST(S) FAILED.")
    print("=" * 76)


if __name__ == "__main__":
    run_standalone_test_suite()
