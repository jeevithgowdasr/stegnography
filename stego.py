"""
LSB Steganography Engine for Lossless Digital Images.

This module provides high-performance Least Significant Bit (LSB) steganography
for embedding and extracting encrypted binary payloads into lossless image carriers (PNG, BMP).

Key Specifications:
    - Pixel Carrier: Least Significant Bit of R, G, B channels (3 carrier bits per pixel).
    - Alpha Preservation: For RGBA images, the Alpha transparency channel (Channel 3) is strictly preserved untouched.
    - Lossless Enforcement: Strictly whitelists .png and .bmp formats to prevent lossy compression corruption.
    - 32-bit Framing: Prefixes all embedded data with a 4-byte big-endian unsigned integer (>I) representing length.
    - Performance: Vectorized NumPy array bit manipulation for ultra-fast embedding and extraction.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Tuple, Union

import numpy as np
from PIL import Image


# =====================================================================
# Constants & Formats Whitelist
# =====================================================================
HEADER_BYTE_LENGTH: int = 4          # 32-bit unsigned integer (struct '>I') for payload length
CARRIER_CHANNELS_PER_PIXEL: int = 3  # R, G, B channels utilized (Alpha is preserved)
SUPPORTED_EXTENSIONS: set[str] = {".png", ".bmp"}
SUPPORTED_PIL_FORMATS: set[str] = {"PNG", "BMP"}


# =====================================================================
# Custom Steganography Exceptions
# =====================================================================
class StegoError(Exception):
    """Base exception for all steganography errors."""
    pass


class CapacityExceededError(StegoError):
    """Raised when the payload size exceeds the cover image's embedding capacity."""
    def __init__(self, required_bytes: int, available_bytes: int):
        self.required_bytes = required_bytes
        self.available_bytes = available_bytes
        super().__init__(
            f"Payload requires {required_bytes:,} bytes, but the cover image only supports {available_bytes:,} bytes."
        )


class UnsupportedFormatError(StegoError):
    """Raised when an unsupported or lossy image format is provided."""
    pass


class ImageValidationError(StegoError):
    """Raised when an image file cannot be loaded or has an invalid/unsupported color mode."""
    pass


class CorruptedPayloadError(StegoError):
    """Raised when the steganographic payload is malformed, truncated, or exceeds capacity."""
    pass


# =====================================================================
# Helper & Validation Functions
# =====================================================================
def _validate_file_path(path: Union[str, Path], must_exist: bool = True) -> Path:
    """Validate and resolve file path format and extension."""
    resolved_path = Path(path).resolve()
    ext = resolved_path.suffix.lower()

    if ext not in SUPPORTED_EXTENSIONS:
        raise UnsupportedFormatError(
            f"Unsupported file extension '{ext}'. Only lossless formats ({', '.join(sorted(SUPPORTED_EXTENSIONS))}) are supported."
        )

    if must_exist and not resolved_path.is_file():
        raise FileNotFoundError(f"Image file not found: {resolved_path}")

    return resolved_path


def _load_image(image_path: Union[str, Path]) -> Tuple[Image.Image, np.ndarray]:
    """
    Open an image, validate its format and color mode, and return PIL Image and NumPy uint8 array.
    """
    path_obj = _validate_file_path(image_path, must_exist=True)

    try:
        img = Image.open(path_obj)
        img.load()  # Ensure full image data is loaded into memory
    except Exception as e:
        raise ImageValidationError(f"Failed to open image file '{path_obj}': {e}") from e

    # Validate image format reported by Pillow
    img_format = img.format.upper() if img.format else path_obj.suffix[1:].upper()
    if img_format not in SUPPORTED_PIL_FORMATS:
        raise UnsupportedFormatError(
            f"Image format '{img_format}' is not supported. Use lossless PNG or BMP images."
        )

    # Validate color mode (RGB or RGBA)
    if img.mode not in ("RGB", "RGBA"):
        raise ImageValidationError(
            f"Unsupported image color mode '{img.mode}'. Only 'RGB' and 'RGBA' images are supported."
        )

    arr = np.array(img, dtype=np.uint8)
    return img, arr


# =====================================================================
# Capacity Calculation
# =====================================================================
def calculate_capacity(image_path: Union[str, Path]) -> int:
    r"""
    Calculate the maximum payload byte capacity available in a lossless cover image.

    Formula:
        $$\text{Capacity (bytes)} = \lfloor \frac{\text{width} \times \text{height} \times 3}{8} \rfloor - \text{HEADER\_BYTE\_LENGTH}$$

    Args:
        image_path: Path to the lossless cover image (.png, .bmp).

    Returns:
        Maximum usable capacity in bytes for secret payload.

    Raises:
        FileNotFoundError: If image file does not exist.
        UnsupportedFormatError: If image format is lossy or unsupported.
        ImageValidationError: If image cannot be read or has invalid dimensions.
    """
    path_obj = _validate_file_path(image_path, must_exist=True)

    try:
        with Image.open(path_obj) as img:
            width, height = img.size
            img_format = img.format.upper() if img.format else path_obj.suffix[1:].upper()
            if img_format not in SUPPORTED_PIL_FORMATS:
                raise UnsupportedFormatError(f"Unsupported format '{img_format}'. Must be PNG or BMP.")
            if img.mode not in ("RGB", "RGBA"):
                raise ImageValidationError(f"Unsupported color mode '{img.mode}'. Must be RGB or RGBA.")
    except (UnsupportedFormatError, ImageValidationError):
        raise
    except Exception as e:
        raise ImageValidationError(f"Error inspecting image dimensions: {e}") from e

    total_carrier_bits = width * height * CARRIER_CHANNELS_PER_PIXEL
    total_carrier_bytes = total_carrier_bits // 8
    usable_capacity = max(0, total_carrier_bytes - HEADER_BYTE_LENGTH)
    return usable_capacity


# =====================================================================
# Core Embedding & Extraction Functions
# =====================================================================
def embed_data(
    cover_image_path: Union[str, Path],
    data: bytes,
    output_stego_path: Union[str, Path],
) -> str:
    """
    Embed arbitrary binary data into the LSBs of a lossless cover image.

    The data is framed with a 4-byte (32-bit) big-endian length prefix.
    If the image has an Alpha channel (RGBA), the Alpha channel is preserved untouched.

    Args:
        cover_image_path: Path to the input cover image (.png, .bmp).
        data: Secret binary payload to embed.
        output_stego_path: Target path to save the generated stego image.

    Returns:
        Absolute string path to the saved stego image.

    Raises:
        CapacityExceededError: If payload exceeds available carrier capacity.
        UnsupportedFormatError: If input/output image format is lossy or unsupported.
        ImageValidationError: If cover image cannot be read.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"Data must be bytes, got {type(data).__name__}")

    out_path_obj = _validate_file_path(output_stego_path, must_exist=False)
    img, img_arr = _load_image(cover_image_path)
    height, width = img_arr.shape[:2]

    # Calculate usable capacity
    total_carrier_bits = width * height * CARRIER_CHANNELS_PER_PIXEL
    max_carrier_bytes = total_carrier_bits // 8
    usable_capacity = max(0, max_carrier_bytes - HEADER_BYTE_LENGTH)

    payload_length = len(data)
    if payload_length > usable_capacity:
        raise CapacityExceededError(required_bytes=payload_length, available_bytes=usable_capacity)

    # Frame packet: 4-byte big-endian length header + raw payload bytes
    header_bytes = struct.pack(">I", payload_length)
    packet_bytes = header_bytes + bytes(data)

    # Unpack packet bytes into individual bits (0 or 1)
    packet_buffer = np.frombuffer(packet_bytes, dtype=np.uint8)
    secret_bits = np.unpackbits(packet_buffer)
    num_bits_to_embed = len(secret_bits)

    # Isolate RGB carrier channels (first 3 channels)
    rgb_channels = img_arr[:, :, :3]
    flat_rgb = rgb_channels.reshape(-1).copy()

    # Clear LSBs and inject secret bits
    flat_rgb[:num_bits_to_embed] = (flat_rgb[:num_bits_to_embed] & 0xFE) | secret_bits
    stego_rgb = flat_rgb.reshape((height, width, 3))

    # Reconstruct full image array
    if img.mode == "RGBA":
        alpha_channel = img_arr[:, :, 3:4]  # Preserve Alpha channel untouched
        stego_arr = np.concatenate((stego_rgb, alpha_channel), axis=2)
    else:
        stego_arr = stego_rgb

    # Ensure parent output directory exists
    out_path_obj.parent.mkdir(parents=True, exist_ok=True)

    # Save lossless stego image
    stego_image = Image.fromarray(stego_arr, mode=img.mode)
    save_format = "PNG" if out_path_obj.suffix.lower() == ".png" else "BMP"
    stego_image.save(out_path_obj, format=save_format)

    return str(out_path_obj)


def extract_data(stego_image_path: Union[str, Path]) -> bytes:
    """
    Extract embedded binary payload from the LSBs of a lossless stego image.

    Reads the 4-byte (32-bit) length prefix first, validates capacity bounds,
    and extracts the exact payload bytes.

    Args:
        stego_image_path: Path to the lossless stego image (.png, .bmp).

    Returns:
        Extracted raw bytes payload.

    Raises:
        CorruptedPayloadError: If the length prefix is invalid or exceeds image capacity.
        UnsupportedFormatError: If image format is lossy or unsupported.
        ImageValidationError: If image cannot be loaded.
    """
    _, img_arr = _load_image(stego_image_path)
    height, width = img_arr.shape[:2]

    # Extract RGB carrier channels and flatten
    rgb_channels = img_arr[:, :, :3]
    flat_rgb = rgb_channels.reshape(-1)
    total_carrier_bits = flat_rgb.size
    max_carrier_bytes = total_carrier_bits // 8

    header_bits_count = HEADER_BYTE_LENGTH * 8
    if total_carrier_bits < header_bits_count:
        raise CorruptedPayloadError("Image is too small to contain a valid 32-bit steganography length header.")

    # 1. Extract the 4-byte length prefix (first 32 LSBs)
    header_bits = flat_rgb[:header_bits_count] & 1
    header_packed = np.packbits(header_bits)[:HEADER_BYTE_LENGTH].tobytes()
    payload_length = struct.unpack(">I", header_packed)[0]

    # 2. Validate payload length against carrier capacity
    max_possible_payload_bytes = max_carrier_bytes - HEADER_BYTE_LENGTH
    if payload_length > max_possible_payload_bytes:
        raise CorruptedPayloadError(
            f"Corrupted payload: Header declared {payload_length:,} bytes, "
            f"which exceeds total available capacity ({max_possible_payload_bytes:,} bytes). "
            f"Image may not contain steganographic data or has been modified."
        )

    # 3. Extract exact payload bits
    payload_bits_count = payload_length * 8
    start_offset = header_bits_count
    end_offset = start_offset + payload_bits_count

    payload_bits = flat_rgb[start_offset:end_offset] & 1
    extracted_bytes = np.packbits(payload_bits)[:payload_length].tobytes()

    return extracted_bytes


# =====================================================================
# Standalone Unit Verification & Demonstration
# =====================================================================
if __name__ == "__main__":
    import shutil
    import tempfile
    import time

    print("========================================================================")
    print("[*] GOOGLE ANTIGRAVITY - IMAGE STEGANOGRAPHY EMBEDDING & EXTRACTION")
    print("    Protocol: Vectorized LSB Engine with 32-bit Framing & RGBA Isolation")
    print("========================================================================")

    temp_dir = Path(tempfile.mkdtemp(prefix="stego_test_"))
    try:
        # 1. Create a synthetic test RGB image (300 x 300 pixels)
        rgb_cover_path = temp_dir / "cover_rgb.png"
        img_w, img_h = 300, 300
        # Generate rich gradient pattern
        x = np.linspace(0, 255, img_w, dtype=np.uint8)
        y = np.linspace(0, 255, img_h, dtype=np.uint8)
        xx, yy = np.meshgrid(x, y)
        test_pattern = np.dstack((xx, yy, (xx + yy) // 2))
        Image.fromarray(test_pattern, mode="RGB").save(rgb_cover_path, format="PNG")

        print(f"\n[+] Step 1: Created Synthetic Cover Image: {rgb_cover_path.name}")
        print(f"    - Dimensions                  : {img_w} x {img_h} (RGB)")
        capacity = calculate_capacity(rgb_cover_path)
        print(f"    - Theoretical Capacity        : {capacity:,} bytes ({capacity / 1024:.2f} KB)")

        # 2. Test Embedding and Extraction with Secret Binary Payload
        test_payload = (
            b"TOP_SECRET_PAYLOAD_V2::AES_GCM_ENCRYPTED_STREAM::"
            + os.urandom(512)
            + b"::END_OF_TRANSMISSION"
        )
        stego_rgb_output = temp_dir / "stego_rgb.png"

        print(f"\n[+] Step 2: Embedding Secret Binary Payload ({len(test_payload):,} bytes)")
        t0 = time.perf_counter()
        embed_data(rgb_cover_path, test_payload, stego_rgb_output)
        t1 = time.perf_counter()
        print(f"    - Stego Output Path           : {stego_rgb_output.name}")
        print(f"    - Embedding Latency           : {(t1 - t0) * 1000:.2f} ms")

        print("\n[+] Step 3: Extracting Payload from Stego Image")
        t2 = time.perf_counter()
        extracted_payload = extract_data(stego_rgb_output)
        t3 = time.perf_counter()
        print(f"    - Extracted Payload Size      : {len(extracted_payload):,} bytes")
        print(f"    - Extraction Latency          : {(t3 - t2) * 1000:.2f} ms")
        assert extracted_payload == test_payload, "Payload byte mismatch!"
        print("    - Status                      : [PASS] EXACT BYTE MATCH VERIFIED")

        # 3. Test RGBA Alpha Channel Transparency Preservation
        print("\n[+] Step 4: Testing RGBA Mode & Alpha Channel Preservation")
        rgba_cover_path = temp_dir / "cover_rgba.png"
        alpha_mask = np.full((img_h, img_w, 1), 180, dtype=np.uint8)  # Semi-transparent Alpha = 180
        rgba_pattern = np.concatenate((test_pattern, alpha_mask), axis=2)
        Image.fromarray(rgba_pattern, mode="RGBA").save(rgba_cover_path, format="PNG")

        stego_rgba_output = temp_dir / "stego_rgba.png"
        embed_data(rgba_cover_path, test_payload, stego_rgba_output)
        extracted_rgba_payload = extract_data(stego_rgba_output)
        assert extracted_rgba_payload == test_payload, "RGBA payload extraction mismatch!"

        # Verify Alpha channel was unaltered
        stego_rgba_arr = np.array(Image.open(stego_rgba_output))
        assert np.array_equal(stego_rgba_arr[:, :, 3], rgba_pattern[:, :, 3]), "Alpha channel was modified!"
        print("    - Alpha Channel Integrity     : [PASS] UNTOUCHED & 100% PRESERVED")
        print("    - RGBA Extraction Status      : [PASS] VERIFIED")

        # 4. Test Capacity Boundary Limits & Exception Raising
        print("\n[+] Step 5: Testing Capacity Boundary Limit and Error Handling")
        oversized_payload = os.urandom(capacity + 1)
        try:
            embed_data(rgb_cover_path, oversized_payload, temp_dir / "overflow.png")
            print("    - Status                      : [FAIL] FAILED (Should have raised CapacityExceededError)")
        except CapacityExceededError as exc:
            print(f"    - Caught Expected Exception   : CapacityExceededError")
            print(f"    - Error Detail                : {exc}")
            print("    - Status                      : [PASS] PROPERLY PREVENTED OVERFLOW")

        # 5. Test Lossless BMP Format Support
        print("\n[+] Step 6: Testing BMP Lossless Format Support")
        bmp_cover_path = temp_dir / "cover.bmp"
        Image.fromarray(test_pattern, mode="RGB").save(bmp_cover_path, format="BMP")
        bmp_stego_path = temp_dir / "stego.bmp"
        embed_data(bmp_cover_path, test_payload, bmp_stego_path)
        extracted_bmp_payload = extract_data(bmp_stego_path)
        assert extracted_bmp_payload == test_payload, "BMP payload extraction mismatch!"
        print("    - BMP Roundtrip Status        : [PASS] VERIFIED")

        # 6. Test Format Rejection on Lossy Formats
        print("\n[+] Step 7: Testing Rejection of Unsupported Formats")
        try:
            _validate_file_path("carrier.jpg")
            print("    - Status                      : [FAIL] FAILED (Should have rejected JPG)")
        except UnsupportedFormatError as exc:
            print(f"    - Caught Expected Exception   : UnsupportedFormatError")
            print(f"    - Status                      : [PASS] LOSSY FORMATS SAFELY BLOCKED")

        print("\n" + "=" * 72)
        print("[SUCCESS] ALL STEGANOGRAPHY TESTS AND ASSERTIONS PASSED SUCCESSFULLY!")
        print("=" * 72)

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
