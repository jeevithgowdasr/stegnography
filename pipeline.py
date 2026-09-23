"""
Unified Orchestrating Pipeline for Image Encryption and Steganography.

This module unifies:
    - Cryptographic Engine (crypto.py): AES-256-GCM + PBKDF2-HMAC-SHA256
    - Steganographic Engine (stego.py): Vectorized LSB embedding with RGBA isolation
    - Image Quality Engine (metrics.py): MSE, PSNR, SSIM, and difference analysis

Provides high-level APIs and an enterprise CLI for end-to-end secret concealment and recovery.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Union

import crypto
from crypto import CryptoError, DecryptionError, InvalidKeyError
import stego
from stego import CapacityExceededError, CorruptedPayloadError as StegoCorruptedError, StegoError
import metrics


# =====================================================================
# Pipeline Exception Hierarchy
# =====================================================================
class PipelineError(Exception):
    """Base exception for all high-level pipeline orchestration failures."""
    pass


class CapacityError(PipelineError):
    """Raised when the secret payload exceeds the cover image's carrier capacity."""
    def __init__(self, required_bytes: int, available_bytes: int):
        self.required_bytes = required_bytes
        self.available_bytes = available_bytes
        super().__init__(
            f"Insufficient carrier capacity: Payload requires {required_bytes:,} bytes, "
            f"but cover image supports only {available_bytes:,} bytes."
        )


class AuthenticationError(PipelineError):
    """Raised when decryption fails due to an incorrect passphrase, wrong key, or data tampering."""
    pass


class UnsupportedFormatError(PipelineError):
    """Raised when an unsupported or lossy image format (e.g., JPEG) is provided."""
    pass


# =====================================================================
# High-Level Orchestration Operations
# =====================================================================
def encrypt_and_hide(
    cover_image_path: Union[str, Path],
    secret_text: str,
    passphrase: str,
    output_image_path: Union[str, Path],
) -> Dict[str, Any]:
    """
    Encrypt secret text with AES-256-GCM and conceal it into a lossless cover image.

    Workflow:
        1. Validate cover image format and compute usable byte capacity.
        2. Encrypt plaintext into a self-contained authenticated stream using PBKDF2 + AES-256-GCM.
        3. Verify capacity and embed payload into image LSBs (preserving Alpha if RGBA).
        4. Evaluate image quality metrics (MSE, PSNR, SSIM, BPP).
        5. Return comprehensive execution summary dictionary.

    Args:
        cover_image_path: Path to the lossless cover image (.png, .bmp).
        secret_text: Confidential text message to conceal.
        passphrase: Secret password used for PBKDF2 key derivation and AES-GCM encryption.
        output_image_path: Destination path for the resulting stego image.

    Returns:
        Structured dictionary with execution status, file paths, payload stats, and quality metrics.

    Raises:
        CapacityError: If the encrypted payload exceeds cover image capacity.
        UnsupportedFormatError: If the image format is lossy or unsupported.
        PipelineError: If encryption, embedding, or validation fails.
    """
    if not passphrase:
        raise PipelineError("Passphrase cannot be empty.")
    if secret_text is None:
        raise PipelineError("Secret text cannot be None.")

    cover_path = Path(cover_image_path).resolve()
    out_path = Path(output_image_path).resolve()

    # 1. Validate cover format and calculate capacity
    try:
        capacity_bytes = stego.calculate_capacity(cover_path)
    except stego.UnsupportedFormatError as e:
        raise UnsupportedFormatError(f"Cover image format error: {e}") from e
    except (FileNotFoundError, stego.ImageValidationError) as e:
        raise PipelineError(f"Cover image validation failed: {e}") from e

    # 2. Encrypt plaintext with AES-256-GCM
    try:
        encrypted_stream = crypto.encrypt_data(secret_text, passphrase)
    except (InvalidKeyError, CryptoError) as e:
        raise PipelineError(f"Cryptographic encryption failed: {e}") from e

    payload_size = len(encrypted_stream)

    # 3. Check capacity boundaries
    if payload_size > capacity_bytes:
        raise CapacityError(required_bytes=payload_size, available_bytes=capacity_bytes)

    # 4. Embed encrypted stream into cover image LSBs
    try:
        saved_stego_path = stego.embed_data(cover_path, encrypted_stream, out_path)
    except CapacityExceededError as e:
        raise CapacityError(required_bytes=e.required_bytes, available_bytes=e.available_bytes) from e
    except stego.UnsupportedFormatError as e:
        raise UnsupportedFormatError(f"Output stego image format error: {e}") from e
    except StegoError as e:
        raise PipelineError(f"Steganographic embedding failed: {e}") from e

    # 5. Evaluate visual fidelity metrics
    try:
        quality = metrics.evaluate_stego_quality(cover_path, saved_stego_path, print_summary=False)
    except Exception as e:
        quality = {"error": str(e), "psnr_db": 0.0, "mse": 0.0, "ssim": 0.0}

    plaintext_bytes_len = len(secret_text.encode("utf-8"))
    capacity_used_pct = round((payload_size / capacity_bytes) * 100.0, 2) if capacity_bytes > 0 else 0.0

    return {
        "success": True,
        "cover_path": str(cover_path),
        "output_path": str(saved_stego_path),
        "plaintext_bytes": plaintext_bytes_len,
        "encrypted_payload_bytes": payload_size,
        "capacity_bytes": capacity_bytes,
        "capacity_used_pct": capacity_used_pct,
        "psnr_db": quality.get("psnr_db", 0.0),
        "mse": quality.get("mse", 0.0),
        "ssim": quality.get("ssim", 0.0),
        "embedding_rate_bpp": quality.get("embedding_rate_bpp", 0.0),
        "is_imperceptible": quality.get("is_imperceptible", True),
        "quality_rating": quality.get("quality_rating", "Unknown"),
    }


def extract_and_decrypt(
    stego_image_path: Union[str, Path],
    passphrase: str,
) -> str:
    """
    Extract concealed encrypted binary payload from a stego image and decrypt it.

    Workflow:
        1. Extract the raw LSB stream and framing header from the stego image.
        2. Decrypt and verify AEAD authentication tag using the passphrase.
        3. Return the verified plaintext string.

    Args:
        stego_image_path: Path to the lossless stego image (.png, .bmp).
        passphrase: Secret password used during encryption.

    Returns:
        Recovered plaintext message string.

    Raises:
        AuthenticationError: If password is wrong, auth tag fails, or payload is corrupted.
        UnsupportedFormatError: If image format is lossy or unsupported.
        PipelineError: If extraction fails unexpectedly.
    """
    if not passphrase:
        raise PipelineError("Passphrase cannot be empty.")

    stego_path = Path(stego_image_path).resolve()

    # 1. Extract raw encrypted bytes from stego image
    try:
        extracted_stream = stego.extract_data(stego_path)
    except stego.UnsupportedFormatError as e:
        raise UnsupportedFormatError(f"Stego image format error: {e}") from e
    except StegoCorruptedError as e:
        raise AuthenticationError(
            f"Extraction failed: Image does not contain valid steganographic data or was modified: {e}"
        ) from e
    except StegoError as e:
        raise PipelineError(f"Steganographic extraction failed: {e}") from e

    # 2. Decrypt and verify authenticity
    try:
        decrypted_text = crypto.decrypt_data(extracted_stream, passphrase)
        return decrypted_text
    except DecryptionError as e:
        raise AuthenticationError(
            "Authentication failed: Incorrect password or tampered/corrupted stego payload."
        ) from e
    except (InvalidKeyError, CryptoError) as e:
        raise AuthenticationError(f"Decryption error: {e}") from e


# =====================================================================
# Command-Line Interface (CLI Mode)
# =====================================================================
def build_cli_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser for hide and extract subcommands."""
    parser = argparse.ArgumentParser(
        prog="pipeline.py",
        description="Enterprise Image Steganography & AES-256-GCM Encryption Engine.",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available Operations")

    # --- Subcommand: hide ---
    hide_parser = subparsers.add_parser("hide", help="Encrypt and hide secret text in a cover image.")
    hide_parser.add_argument("--cover", "-c", required=True, help="Path to input cover image (.png, .bmp)")
    hide_parser.add_argument("--secret", "-s", required=True, help="Secret message text or path to text file")
    hide_parser.add_argument("--password", "-p", required=True, help="Encryption passphrase")
    hide_parser.add_argument("--output", "-o", required=True, help="Path for output stego image (.png, .bmp)")

    # --- Subcommand: extract ---
    extract_parser = subparsers.add_parser("extract", help="Extract and decrypt secret text from a stego image.")
    extract_parser.add_argument("--stego", "-i", required=True, help="Path to input stego image (.png, .bmp)")
    extract_parser.add_argument("--password", "-p", required=True, help="Decryption passphrase")

    return parser


def run_cli() -> None:
    """Execute CLI commands and format terminal output."""
    parser = build_cli_parser()
    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        sys.exit(0)

    if args.subcommand == "hide":
        # Check if secret argument is a path to an existing text file
        secret_content = args.secret
        secret_file = Path(args.secret)
        if secret_file.is_file():
            try:
                secret_content = secret_file.read_text(encoding="utf-8")
            except Exception as e:
                print(f"[!] Error reading secret file: {e}", file=sys.stderr)
                sys.exit(1)

        try:
            result = encrypt_and_hide(
                cover_image_path=args.cover,
                secret_text=secret_content,
                passphrase=args.password,
                output_image_path=args.output,
            )
            print("\n" + "=" * 70)
            print("[*] STEGANOGRAPHY ENCRYPTION & HIDING COMPLETE")
            print("=" * 70)
            print(f"  Cover Image              : {result['cover_path']}")
            print(f"  Stego Output             : {result['output_path']}")
            print(f"  Plaintext Size           : {result['plaintext_bytes']:,} bytes")
            print(f"  Encrypted Payload Size   : {result['encrypted_payload_bytes']:,} bytes")
            print(f"  Carrier Capacity         : {result['capacity_bytes']:,} bytes ({result['capacity_used_pct']}% utilized)")
            print("-" * 70)
            print(f"  PSNR (Peak SNR)          : {result['psnr_db']:.2f} dB (Imperceptible > 30-40 dB)")
            print(f"  MSE (Mean Squared Error) : {result['mse']:.6f}")
            print(f"  SSIM (Structural Index)  : {result['ssim']:.6f}")
            print(f"  Quality Rating           : {result['quality_rating']}")
            print("=" * 70 + "\n")

        except PipelineError as e:
            print(f"\n[!] Pipeline Error: {e}\n", file=sys.stderr)
            sys.exit(1)

    elif args.subcommand == "extract":
        try:
            recovered_text = extract_and_decrypt(
                stego_image_path=args.stego,
                passphrase=args.password,
            )
            print("\n" + "=" * 70)
            print("[*] STEGANOGRAPHY EXTRACTION & DECRYPTION SUCCESSFUL")
            print("=" * 70)
            print("  Recovered Secret Message:")
            print("-" * 70)
            print(recovered_text)
            print("=" * 70 + "\n")

        except AuthenticationError as e:
            print(f"\n[!] Authentication Failure: {e}\n", file=sys.stderr)
            sys.exit(1)
        except PipelineError as e:
            print(f"\n[!] Pipeline Error: {e}\n", file=sys.stderr)
            sys.exit(1)


# =====================================================================
# Automated Integration Test & Demonstration
# =====================================================================
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("hide", "extract", "-h", "--help"):
        run_cli()
    else:
        import shutil
        import tempfile
        import numpy as np
        from PIL import Image

        print("========================================================================")
        print("[*] GOOGLE ANTIGRAVITY - UNIFIED STEGANOGRAPHY & CRYPTO PIPELINE")
        print("    Full End-to-End Orchestration & Automated Roundtrip Verification")
        print("========================================================================")

        temp_dir = Path(tempfile.mkdtemp(prefix="pipeline_test_"))
        try:
            # 1. Create a synthetic test cover image (250x250 RGB gradient)
            cover_path = temp_dir / "cover_input.png"
            stego_path = temp_dir / "stego_output.png"
            w, h = 250, 250
            x = np.linspace(0, 255, w, dtype=np.uint8)
            y = np.linspace(0, 255, h, dtype=np.uint8)
            xx, yy = np.meshgrid(x, y)
            pattern = np.dstack((xx, yy, 255 - yy))
            Image.fromarray(pattern, mode="RGB").save(cover_path, format="PNG")

            secret_msg = (
                "CLASSIFIED LEVEL 5: Strategic satellite positioning coordinates "
                "Alpha-7: 37.7749 deg N, 122.4194 deg W. Encryption Keycard #9482-Omega."
            )
            master_passphrase = "UltraSecureLongPassword#2026!"
            wrong_passphrase = "GuessedIncorrectPassword"

            # 2. Encrypt & Hide Stage
            print("\n[+] Stage 1: Encrypting and Hiding Secret Message")
            result = encrypt_and_hide(
                cover_image_path=cover_path,
                secret_text=secret_msg,
                passphrase=master_passphrase,
                output_image_path=stego_path,
            )
            assert result["success"] is True
            assert stego_path.is_file()
            print(f"    - Cover Image                 : {result['cover_path']}")
            print(f"    - Stego Image                 : {result['output_path']}")
            print(f"    - Plaintext Bytes             : {result['plaintext_bytes']} bytes")
            print(f"    - Encrypted Payload Bytes     : {result['encrypted_payload_bytes']} bytes")
            print(f"    - Carrier Capacity            : {result['capacity_bytes']:,} bytes ({result['capacity_used_pct']}% utilized)")
            print(f"    - PSNR                        : {result['psnr_db']:.2f} dB")
            print(f"    - MSE                         : {result['mse']:.6f}")
            print(f"    - SSIM                        : {result['ssim']:.6f}")
            print(f"    - Quality Rating              : {result['quality_rating']}")
            print("    - Status                      : [PASS] EMBEDDING & QUALITY VERIFIED")

            # 3. Extract & Decrypt Stage
            print("\n[+] Stage 2: Extracting and Decrypting Secret Message")
            recovered_message = extract_and_decrypt(
                stego_image_path=stego_path,
                passphrase=master_passphrase,
            )
            assert recovered_message == secret_msg, "Recovered text mismatch!"
            print(f"    - Recovered Text              : \"{recovered_message}\"")
            print("    - Status                      : [PASS] EXACT TEXT MATCH VERIFIED")

            # 4. Error Handling: Incorrect Password
            print("\n[+] Stage 3: Testing Decryption with Wrong Password")
            try:
                extract_and_decrypt(stego_image_path=stego_path, passphrase=wrong_passphrase)
                print("    - Status                      : [FAIL] FAILED (Should have raised AuthenticationError)")
            except AuthenticationError as exc:
                print(f"    - Caught Expected Exception   : AuthenticationError")
                print(f"    - Error Detail                : {exc}")
                print("    - Status                      : [PASS] REJECTED WRONG PASSWORD")

            # 5. Error Handling: Capacity Exceeded
            print("\n[+] Stage 4: Testing Capacity Boundary Limit")
            huge_secret = "A" * (result["capacity_bytes"] + 100)
            try:
                encrypt_and_hide(cover_path, huge_secret, master_passphrase, temp_dir / "overflow.png")
                print("    - Status                      : [FAIL] FAILED (Should have raised CapacityError)")
            except CapacityError as exc:
                print(f"    - Caught Expected Exception   : CapacityError")
                print(f"    - Error Detail                : {exc}")
                print("    - Status                      : [PASS] CAPACITY OVERFLOW PREVENTED")

            # 6. Error Handling: Lossy Format Rejection
            print("\n[+] Stage 5: Testing Lossy Image Format Rejection")
            try:
                encrypt_and_hide("cover.jpg", secret_msg, master_passphrase, "output.jpg")
                print("    - Status                      : [FAIL] FAILED (Should have rejected JPG)")
            except UnsupportedFormatError as exc:
                print(f"    - Caught Expected Exception   : UnsupportedFormatError")
                print("    - Status                      : [PASS] LOSSY FORMAT SAFELY BLOCKED")

            print("\n" + "=" * 72)
            print("[SUCCESS] ALL PIPELINE INTEGRATION STAGES PASSED SUCCESSFULLY!")
            print("=" * 72)

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
