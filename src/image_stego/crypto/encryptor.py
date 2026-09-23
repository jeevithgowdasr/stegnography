"""Authenticated symmetric encryption and decryption using AES-256-GCM."""

import os
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from ..core.exceptions import DecryptionError
from .kdf import derive_key, generate_salt

NONCE_LENGTH = 12  # Standard 96-bit nonce for AES-GCM
TAG_LENGTH = 16    # 128-bit authentication tag appended by AESGCM


def encrypt_data(
    plaintext: bytes,
    password: str,
    salt: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext bytes using AES-256-GCM.
    
    Args:
        plaintext: The raw bytes to encrypt.
        password: User secret password.
        salt: Optional salt; generated randomly if not provided.
        nonce: Optional 12-byte nonce; generated randomly if not provided.
        
    Returns:
        Tuple of (ciphertext_with_auth_tag, salt, nonce).
    """
    if salt is None:
        salt = generate_salt()
    if nonce is None:
        nonce = os.urandom(NONCE_LENGTH)

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    return ciphertext_with_tag, salt, nonce


def decrypt_data(
    ciphertext_with_tag: bytes,
    password: str,
    salt: bytes,
    nonce: bytes,
) -> bytes:
    """
    Decrypt ciphertext bytes using AES-256-GCM and verify integrity.
    
    Args:
        ciphertext_with_tag: The encrypted payload including the 16-byte auth tag.
        password: User secret password.
        salt: 16-byte salt used during encryption.
        nonce: 12-byte nonce used during encryption.
        
    Returns:
        Decrypted plaintext bytes.
        
    Raises:
        DecryptionError: If the password is incorrect or ciphertext has been altered.
    """
    try:
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)
        return plaintext
    except InvalidTag as e:
        raise DecryptionError(
            "Authentication failed: Incorrect password or modified/corrupted image data."
        ) from e
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {str(e)}") from e
