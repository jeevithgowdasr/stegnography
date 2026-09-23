"""
Cryptographic Engine for Image Steganography & Data Protection.

This module provides enterprise-grade, authenticated symmetric encryption (AES-256-GCM)
and secure key derivation (PBKDF2-HMAC-SHA256) using the Python `cryptography` library.
It is engineered to secure payloads before steganographic embedding into cover images.

Key Features:
    - AES-256-GCM: Authenticated Encryption with Associated Data (AEAD).
      Ensures confidentiality, authenticity, and integrity with 128-bit tag verification.
    - PBKDF2-HMAC-SHA256: Resistant against brute-force and dictionary attacks with 100,000+ iterations.
    - EncryptedPayload: Self-contained dataclass handling serialization (bytes, base64, hex)
      for direct compatibility with LSB steganography pipelines.
    - Robust Error Handling: Granular exceptions (DecryptionError, InvalidKeyError, CorruptedDataError).
"""

from __future__ import annotations

import base64
import os
import struct
from dataclasses import dataclass
from typing import Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# =====================================================================
# Constants & Cryptographic Parameters
# =====================================================================
SALT_BYTE_LENGTH: int = 16          # 128-bit cryptographically random salt
NONCE_BYTE_LENGTH: int = 12         # 96-bit standard nonce for AES-GCM (NIST SP 800-38D)
KEY_BYTE_LENGTH: int = 32           # 256-bit symmetric encryption key
TAG_BYTE_LENGTH: int = 16           # 128-bit authentication tag appended by AES-GCM
PBKDF2_DEFAULT_ITERATIONS: int = 100_000  # OWASP recommended minimum for PBKDF2-HMAC-SHA256
PAYLOAD_HEADER_MAGIC: bytes = b"STG1"      # 4-byte Magic header for serialized payload validation


# =====================================================================
# Custom Cryptographic Exceptions
# =====================================================================
class CryptoError(Exception):
    """Base exception for all cryptographic failures in the steganography engine."""
    pass


class InvalidKeyError(CryptoError):
    """Raised when an encryption key, passphrase, or salt parameter is malformed or invalid."""
    pass


class DecryptionError(CryptoError):
    """
    Raised when decryption fails due to an incorrect passphrase, wrong key,
    or authentication tag mismatch (tampering/corruption).
    """
    pass


class CorruptedDataError(CryptoError):
    """Raised when the serialized encrypted payload is malformed, truncated, or corrupted."""
    pass


# =====================================================================
# Encrypted Payload Container
# =====================================================================
@dataclass(frozen=True)
class EncryptedPayload:
    """
    Encapsulates all components necessary for AES-256-GCM authenticated decryption.

    Attributes:
        salt: 16-byte random salt used during PBKDF2 key derivation (or empty if raw key was supplied).
        nonce: 12-byte initialization vector / nonce for AES-GCM.
        ciphertext: Encrypted data including the 16-byte authentication tag at the end.
    """
    salt: bytes
    nonce: bytes
    ciphertext: bytes

    def __post_init__(self) -> None:
        if self.salt and len(self.salt) < 16:
            raise InvalidKeyError(f"Salt must be at least 16 bytes, received {len(self.salt)} bytes.")
        if len(self.nonce) != NONCE_BYTE_LENGTH:
            raise InvalidKeyError(f"AES-GCM nonce must be exactly {NONCE_BYTE_LENGTH} bytes, received {len(self.nonce)} bytes.")
        if len(self.ciphertext) < TAG_BYTE_LENGTH:
            raise CorruptedDataError(
                f"Ciphertext must include at least {TAG_BYTE_LENGTH} bytes for authentication tag."
            )

    @property
    def auth_tag(self) -> bytes:
        """Extract the trailing 16-byte GCM authentication tag."""
        return self.ciphertext[-TAG_BYTE_LENGTH:]

    @property
    def raw_ciphertext(self) -> bytes:
        """Extract the encrypted ciphertext excluding the auth tag."""
        return self.ciphertext[:-TAG_BYTE_LENGTH]

    def to_bytes(self) -> bytes:
        """
        Serialize payload into a binary stream ideal for steganographic embedding.
        
        Binary Format:
            [4 bytes Magic: 'STG1']
            [2 bytes Salt Length (uint16)]
            [N bytes Salt]
            [12 bytes Nonce]
            [M bytes Ciphertext + Tag]
        """
        salt_len = len(self.salt)
        header = struct.pack("!4sH", PAYLOAD_HEADER_MAGIC, salt_len)
        return header + self.salt + self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> EncryptedPayload:
        """
        Deserialize binary data into an EncryptedPayload instance.
        
        Raises:
            CorruptedDataError: If magic bytes are missing or payload is truncated.
        """
        min_header_size = 6  # 4 bytes magic + 2 bytes salt_len
        if len(data) < min_header_size + NONCE_BYTE_LENGTH + TAG_BYTE_LENGTH:
            raise CorruptedDataError("Payload is too short to be a valid encrypted stego stream.")

        magic, salt_len = struct.unpack("!4sH", data[:min_header_size])
        if magic != PAYLOAD_HEADER_MAGIC:
            raise CorruptedDataError(f"Invalid payload magic header: {magic!r}. Expected {PAYLOAD_HEADER_MAGIC!r}.")

        offset = min_header_size
        if len(data) < offset + salt_len + NONCE_BYTE_LENGTH + TAG_BYTE_LENGTH:
            raise CorruptedDataError("Payload is truncated or corrupted (insufficient data for salt/nonce/tag).")

        salt = data[offset : offset + salt_len]
        offset += salt_len

        nonce = data[offset : offset + NONCE_BYTE_LENGTH]
        offset += NONCE_BYTE_LENGTH

        ciphertext = data[offset:]
        return cls(salt=salt, nonce=nonce, ciphertext=ciphertext)

    def to_base64(self) -> str:
        """Encode binary payload to URL-safe Base64 string."""
        return base64.urlsafe_b64encode(self.to_bytes()).decode("ascii")

    @classmethod
    def from_base64(cls, b64_str: str) -> EncryptedPayload:
        """Decode Base64 string to an EncryptedPayload."""
        try:
            raw = base64.urlsafe_b64decode(b64_str.encode("ascii"))
            return cls.from_bytes(raw)
        except Exception as e:
            raise CorruptedDataError(f"Failed to decode base64 payload: {e}") from e


# =====================================================================
# Key Derivation & Random Generators
# =====================================================================
def generate_salt(length: int = SALT_BYTE_LENGTH) -> bytes:
    """Generate cryptographically secure pseudo-random salt using OS CSPRNG."""
    return os.urandom(length)


def generate_nonce(length: int = NONCE_BYTE_LENGTH) -> bytes:
    """Generate cryptographically secure 96-bit nonce for AES-GCM."""
    return os.urandom(length)


def derive_key(
    passphrase: Union[str, bytes],
    salt: bytes,
    iterations: int = PBKDF2_DEFAULT_ITERATIONS,
    key_length: int = KEY_BYTE_LENGTH,
) -> bytes:
    """
    Derive a 256-bit symmetric encryption key from a user passphrase using PBKDF2-HMAC-SHA256.

    Args:
        passphrase: Secret passphrase (str or bytes).
        salt: Random cryptographic salt (at least 16 bytes).
        iterations: Number of PBKDF2 hash iterations (default: 100,000).
        key_length: Length of derived key in bytes (default: 32 bytes / 256 bits).

    Returns:
        32-byte derived symmetric key.

    Raises:
        InvalidKeyError: If passphrase is empty or salt is invalid.
    """
    if not passphrase:
        raise InvalidKeyError("Passphrase cannot be empty.")
    if not salt or len(salt) < 16:
        raise InvalidKeyError(f"Salt must be at least 16 bytes, received {len(salt) if salt else 0} bytes.")
    if iterations < 10_000:
        raise InvalidKeyError("Iterations count is too low for secure PBKDF2 derivation.")

    passphrase_bytes = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase_bytes)


# =====================================================================
# Symmetric Encryption & Decryption Engine
# =====================================================================
def encrypt(
    plaintext: Union[str, bytes],
    key_or_passphrase: Union[str, bytes],
    salt: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
    associated_data: Optional[bytes] = None,
    iterations: int = PBKDF2_DEFAULT_ITERATIONS,
) -> EncryptedPayload:
    """
    Encrypt plaintext using AES-256-GCM authenticated encryption.

    Args:
        plaintext: Confidential message to encrypt (string or raw bytes).
        key_or_passphrase: User passphrase (string or bytes) or raw 32-byte key.
        salt: Optional salt. If not provided and passphrase is used, a 16-byte salt is generated.
        nonce: Optional 12-byte nonce. If not provided, a CSPRNG nonce is generated.
        associated_data: Optional authenticated data verified during decryption without encryption.
        iterations: Number of PBKDF2 iterations if key derivation is performed.

    Returns:
        EncryptedPayload containing salt, nonce, and ciphertext (with 16-byte auth tag).

    Raises:
        InvalidKeyError: If the key/passphrase parameters are invalid.
        CryptoError: If encryption fails unexpectedly.
    """
    if plaintext is None:
        raise CryptoError("Plaintext cannot be None.")

    plaintext_bytes = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext

    # Determine if key_or_passphrase is a raw 32-byte key or a passphrase requiring PBKDF2
    is_raw_key = isinstance(key_or_passphrase, bytes) and len(key_or_passphrase) == KEY_BYTE_LENGTH and salt is None

    if is_raw_key:
        symmetric_key = key_or_passphrase
        used_salt = b""
    else:
        used_salt = salt if salt is not None else generate_salt(SALT_BYTE_LENGTH)
        symmetric_key = derive_key(key_or_passphrase, used_salt, iterations=iterations)

    used_nonce = nonce if nonce is not None else generate_nonce(NONCE_BYTE_LENGTH)

    try:
        aesgcm = AESGCM(symmetric_key)
        ciphertext_with_tag = aesgcm.encrypt(used_nonce, plaintext_bytes, associated_data)
        return EncryptedPayload(salt=used_salt, nonce=used_nonce, ciphertext=ciphertext_with_tag)
    except Exception as e:
        raise CryptoError(f"Encryption failed: {e}") from e


def decrypt(
    payload: Union[EncryptedPayload, bytes, str],
    key_or_passphrase: Union[str, bytes],
    associated_data: Optional[bytes] = None,
    iterations: int = PBKDF2_DEFAULT_ITERATIONS,
    return_bytes: bool = False,
) -> Union[str, bytes]:
    """
    Decrypt an AES-256-GCM encrypted payload and verify authenticity and integrity.

    Args:
        payload: EncryptedPayload object, serialized binary bytes, or base64 string.
        key_or_passphrase: The passphrase or raw 32-byte key used for encryption.
        associated_data: Optional authenticated data that must match encryption.
        iterations: Number of PBKDF2 iterations if passphrase was used.
        return_bytes: If True, returns decrypted raw bytes; otherwise decodes to UTF-8 str.

    Returns:
        Decrypted plaintext as a string (default) or bytes (if return_bytes=True).

    Raises:
        DecryptionError: If the passphrase is incorrect or data was tampered with (InvalidTag).
        InvalidKeyError: If the key/passphrase is invalid.
        CorruptedDataError: If the payload structure is corrupted or truncated.
    """
    # Normalize payload into EncryptedPayload instance
    if isinstance(payload, str):
        target_payload = EncryptedPayload.from_base64(payload)
    elif isinstance(payload, bytes):
        target_payload = EncryptedPayload.from_bytes(payload)
    elif isinstance(payload, EncryptedPayload):
        target_payload = payload
    else:
        raise CorruptedDataError(f"Unsupported payload type: {type(payload).__name__}")

    # Determine symmetric key
    if target_payload.salt:
        symmetric_key = derive_key(key_or_passphrase, target_payload.salt, iterations=iterations)
    else:
        # Raw key mode
        if isinstance(key_or_passphrase, bytes) and len(key_or_passphrase) == KEY_BYTE_LENGTH:
            symmetric_key = key_or_passphrase
        else:
            raise InvalidKeyError("Payload has no salt; a valid 32-byte raw key is required.")

    try:
        aesgcm = AESGCM(symmetric_key)
        decrypted_bytes = aesgcm.decrypt(
            target_payload.nonce,
            target_payload.ciphertext,
            associated_data,
        )

        if return_bytes:
            return decrypted_bytes
        try:
            return decrypted_bytes.decode("utf-8")
        except UnicodeDecodeError:
            # If plaintext was binary, return raw bytes
            return decrypted_bytes

    except InvalidTag as e:
        raise DecryptionError(
            "Authentication tag verification failed: Incorrect passphrase/key or tampered/corrupted ciphertext."
        ) from e
    except (InvalidKeyError, CorruptedDataError):
        raise
    except Exception as e:
        raise DecryptionError(f"Decryption failed unexpectedly: {e}") from e


def encrypt_data(
    plaintext: Union[str, bytes],
    passphrase: str,
    salt: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
) -> bytes:
    """
    Encrypt plaintext into a self-contained binary payload stream (Magic + Salt + Nonce + Ciphertext + Tag).
    Ideal for direct steganographic embedding.
    """
    payload = encrypt(plaintext, passphrase, salt=salt, nonce=nonce)
    return payload.to_bytes()


def decrypt_data(
    payload_bytes: Union[bytes, EncryptedPayload, str],
    passphrase: str,
) -> str:
    """
    Decrypt a self-contained binary payload stream using the passphrase.
    """
    return str(decrypt(payload_bytes, passphrase, return_bytes=False))



# =====================================================================
# Standalone Unit Verification & Demonstration
# =====================================================================
if __name__ == "__main__":
    import time

    print("========================================================================")
    print("[*] GOOGLE ANTIGRAVITY - IMAGE STEGANOGRAPHY CRYPTOGRAPHIC ENGINE")
    print("    Protocol: AES-256-GCM with PBKDF2-HMAC-SHA256 Key Derivation")
    print("========================================================================")

    sample_secret = "CONFIDENTIAL: Operation Starlight coordinates: 37.7749° N, 122.4194° W. Keycard #9481-Alpha."
    passphrase = "CorrectHorseBatteryStaple#2026!"
    wrong_passphrase = "WrongPasswordGuessAttempt@404"

    print("\n[+] Step 1: Generating Salt and Deriving 256-bit AES Key")
    salt = generate_salt(16)
    t0 = time.perf_counter()
    derived_key = derive_key(passphrase, salt, iterations=PBKDF2_DEFAULT_ITERATIONS)
    t1 = time.perf_counter()
    print(f"    - PBKDF2 Salt (16 bytes)      : {salt.hex()}")
    print(f"    - Iterations                  : {PBKDF2_DEFAULT_ITERATIONS:,}")
    print(f"    - Derived Key (32 bytes / 256-bit): {derived_key.hex()[:32]}... [REDACTED]")
    print(f"    - Derivation Latency          : {(t1 - t0) * 1000:.2f} ms")

    print("\n[+] Step 2: Encrypting Secret Plaintext (AES-256-GCM)")
    print(f"    - Plaintext                   : \"{sample_secret}\"")
    payload = encrypt(sample_secret, passphrase, salt=salt)
    print(f"    - Nonce / IV (12 bytes)       : {payload.nonce.hex()}")
    print(f"    - Raw Ciphertext ({len(payload.raw_ciphertext)} bytes)   : {payload.raw_ciphertext.hex()[:40]}...")
    print(f"    - Auth Tag (16 bytes / 128-bit): {payload.auth_tag.hex()}")
    print(f"    - Base64 Encoded Stream       : {payload.to_base64()[:48]}...")

    print("\n[+] Step 3: Binary Serialization for Steganographic Carrier")
    serialized_bytes = payload.to_bytes()
    print(f"    - Serialized Stream Size      : {len(serialized_bytes)} bytes")
    print(f"    - Header Magic                : {serialized_bytes[:4]!r}")

    print("\n[+] Step 4: Successful Decryption Verification")
    recovered_text = decrypt(serialized_bytes, passphrase)
    print(f"    - Decrypted Output            : \"{recovered_text}\"")
    assert recovered_text == sample_secret, "Decryption mismatch!"
    print("    - Status                      : [PASS] MATCH VERIFIED (Confidentiality & Integrity Confirmed)")

    print("\n[+] Step 5: Testing Decryption with Wrong Passphrase (Error Handling)")
    try:
        decrypt(serialized_bytes, wrong_passphrase)
        print("    - Status                      : [FAIL] FAILED (Should have raised DecryptionError)")
    except DecryptionError as exc:
        print(f"    - Caught Expected Exception   : DecryptionError")
        print(f"    - Error Detail                : {exc}")
        print("    - Status                      : [PASS] PROPERLY REJECTED INVALID KEY")

    print("\n[+] Step 6: Testing Tamper Detection (AEAD Integrity Check)")
    # Corrupt 1 byte in ciphertext
    tampered_bytes = bytearray(serialized_bytes)
    tampered_bytes[-1] ^= 0xFF  # Flip bits in authentication tag
    try:
        decrypt(bytes(tampered_bytes), passphrase)
        print("    - Status                      : [FAIL] FAILED (Should have rejected corrupted payload)")
    except DecryptionError as exc:
        print(f"    - Caught Expected Exception   : DecryptionError")
        print(f"    - Error Detail                : {exc}")
        print("    - Status                      : [PASS] TAMPERING SUCCESSFULLY DETECTED")

    print("\n[+] Step 7: Testing Direct Raw 32-Byte Key Mode")
    raw_key = os.urandom(32)
    raw_payload = encrypt("Direct Key Message Test", raw_key)
    raw_decrypted = decrypt(raw_payload, raw_key)
    assert raw_decrypted == "Direct Key Message Test"
    print(f"    - Raw Key Decrypted           : \"{raw_decrypted}\"")
    print("    - Status                      : [PASS] RAW KEY MODE VERIFIED")

    print("\n" + "=" * 72)
    print("[SUCCESS] ALL CRYPTOGRAPHIC TESTS AND ASSERTIONS PASSED SUCCESSFULLY!")
    print("=" * 72)
