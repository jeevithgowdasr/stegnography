"""Key Derivation Function (KDF) using PBKDF2-HMAC-SHA256."""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

SALT_LENGTH = 16
PBKDF2_ITERATIONS = 100_000
KEY_LENGTH = 32  # 256 bits for AES-256


def generate_salt(length: int = SALT_LENGTH) -> bytes:
    """Generate cryptographically secure random salt."""
    return os.urandom(length)


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """
    Derive a 256-bit symmetric encryption key from a string password and salt.
    
    Args:
        password: User-provided passphrase.
        salt: 16-byte cryptographic salt.
        iterations: Number of hash iterations (default 100,000).
        
    Returns:
        32-byte derived AES-256 key.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    if len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes.")

    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password_bytes)
