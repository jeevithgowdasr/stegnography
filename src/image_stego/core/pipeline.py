"""High-level orchestration pipeline for Image Steganography and Encryption."""

import os
from pathlib import Path
from typing import Optional, Union

from .exceptions import StegoError, ImageCapacityExceededError
from .models import PayloadType, EmbeddingResult, ExtractionResult
from ..crypto.encryptor import encrypt_data, decrypt_data
from ..stego.header import pack_header
from ..stego.capacity import calculate_image_capacity
from ..stego.lsb_encoder import embed_bits
from ..stego.lsb_decoder import extract_stego_packet
from ..utils.image_io import load_image, save_image
from ..utils.validators import validate_image_path, validate_output_path


def encrypt_and_hide(
    cover_image_path: Union[str, Path],
    password: str,
    secret_text: Optional[str] = None,
    secret_file_path: Optional[Union[str, Path]] = None,
    output_image_path: Optional[Union[str, Path]] = None,
) -> EmbeddingResult:
    """
    Encrypt plaintext or file data with AES-256-GCM and embed into a cover image.
    
    Args:
        cover_image_path: Path to the lossless cover image (PNG/BMP).
        password: User secret password for PBKDF2/AES-GCM.
        secret_text: Text message to embed.
        secret_file_path: Path to a file to embed.
        output_image_path: Output path for the stego image (defaults to <cover>_stego.png).
        
    Returns:
        EmbeddingResult containing operation details.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    if secret_text is None and secret_file_path is None:
        raise ValueError("Either secret_text or secret_file_path must be provided.")

    cover_path = validate_image_path(cover_image_path, must_exist=True)
    img_array, (width, height) = load_image(cover_path)
    total_capacity = calculate_image_capacity(width, height, channels=3)

    # Determine payload type and prepare raw bytes
    if secret_file_path is not None:
        file_path = Path(secret_file_path)
        if not file_path.is_file():
            raise FileNotFoundError(f"Secret file not found: {file_path}")
        raw_payload = file_path.read_bytes()
        filename = file_path.name
        payload_type = PayloadType.FILE
        is_file = True
    else:
        raw_payload = secret_text.encode("utf-8")
        filename = None
        payload_type = PayloadType.TEXT
        is_file = False

    # Encrypt the raw payload
    ciphertext_with_tag, salt, nonce = encrypt_data(raw_payload, password)

    # Pack the binary header with salt, nonce, and metadata
    header_bytes = pack_header(
        payload_type=payload_type,
        salt=salt,
        nonce=nonce,
        payload_length=len(ciphertext_with_tag),
        filename=filename,
    )

    total_packet = header_bytes + ciphertext_with_tag
    if len(total_packet) > total_capacity:
        raise ImageCapacityExceededError(
            required_bytes=len(total_packet),
            available_bytes=total_capacity,
        )

    # Embed bits into image LSBs
    stego_array = embed_bits(img_array, total_packet)

    # Determine default output path if not specified
    if output_image_path is None:
        output_image_path = cover_path.parent / f"{cover_path.stem}_stego.png"
    else:
        output_image_path = validate_output_path(output_image_path)

    saved_path = save_image(stego_array, output_image_path)

    capacity_used_pct = round((len(total_packet) / total_capacity) * 100, 2)

    return EmbeddingResult(
        cover_path=str(cover_path),
        output_path=str(saved_path),
        payload_bytes=len(raw_payload),
        capacity_bytes=total_capacity,
        capacity_used_pct=capacity_used_pct,
        is_file=is_file,
        filename=filename,
    )


def extract_and_decrypt(
    stego_image_path: Union[str, Path],
    password: str,
    output_directory: Optional[Union[str, Path]] = None,
) -> ExtractionResult:
    """
    Extract embedded data from a stego image and decrypt it with AES-256-GCM.
    
    Args:
        stego_image_path: Path to the stego image.
        password: User secret password.
        output_directory: Directory where extracted secret files will be saved (if payload is a file).
        
    Returns:
        ExtractionResult containing decrypted text or file metadata.
    """
    if not password:
        raise ValueError("Password cannot be empty.")

    stego_path = validate_image_path(stego_image_path, must_exist=True)
    img_array, _ = load_image(stego_path)

    # Extract header and ciphertext from LSBs
    header, ciphertext_with_tag = extract_stego_packet(img_array)

    # Decrypt and authenticate ciphertext
    plaintext_bytes = decrypt_data(
        ciphertext_with_tag=ciphertext_with_tag,
        password=password,
        salt=header.salt,
        nonce=header.nonce,
    )

    if header.payload_type == PayloadType.TEXT:
        text_content = plaintext_bytes.decode("utf-8", errors="replace")
        return ExtractionResult(
            payload_type=PayloadType.TEXT,
            text_content=text_content,
        )
    else:
        filename = header.filename or "extracted_secret.bin"
        output_file_path = None

        if output_directory is not None:
            out_dir = Path(output_directory)
            out_dir.mkdir(parents=True, exist_ok=True)
            target_file = out_dir / filename
            target_file.write_bytes(plaintext_bytes)
            output_file_path = str(target_file)

        return ExtractionResult(
            payload_type=PayloadType.FILE,
            binary_content=plaintext_bytes,
            filename=filename,
            output_file_path=output_file_path,
        )
