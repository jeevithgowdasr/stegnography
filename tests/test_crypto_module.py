"""Unit tests for crypto.py module."""

import pytest
import os
from crypto import (
    encrypt,
    decrypt,
    derive_key,
    generate_salt,
    generate_nonce,
    EncryptedPayload,
    CryptoError,
    DecryptionError,
    InvalidKeyError,
    CorruptedDataError,
)


def test_derive_key_deterministic_and_unique():
    passphrase = "SecurePassphrase2026!"
    salt1 = generate_salt(16)
    salt2 = generate_salt(16)

    key1 = derive_key(passphrase, salt1, iterations=10_000)
    key2 = derive_key(passphrase, salt1, iterations=10_000)
    key3 = derive_key(passphrase, salt2, iterations=10_000)

    assert len(key1) == 32
    assert key1 == key2
    assert key1 != key3


def test_derive_key_invalid_inputs():
    salt = generate_salt(16)
    with pytest.raises(InvalidKeyError, match="Passphrase cannot be empty"):
        derive_key("", salt)

    with pytest.raises(InvalidKeyError, match="Salt must be at least 16 bytes"):
        derive_key("password", b"short")

    with pytest.raises(InvalidKeyError, match="Iterations count is too low"):
        derive_key("password", salt, iterations=100)


def test_encrypt_decrypt_str_roundtrip():
    secret = "Top Secret Operation Antigravity payload."
    passphrase = "SuperStrongPassword987!"

    payload = encrypt(secret, passphrase)
    assert isinstance(payload, EncryptedPayload)
    assert len(payload.salt) == 16
    assert len(payload.nonce) == 12
    assert len(payload.auth_tag) == 16

    decrypted = decrypt(payload, passphrase)
    assert decrypted == secret


def test_encrypt_decrypt_bytes_roundtrip():
    secret_bytes = os.urandom(64)
    passphrase = "BytePayloadPassword"

    payload = encrypt(secret_bytes, passphrase)
    decrypted_bytes = decrypt(payload, passphrase, return_bytes=True)
    assert decrypted_bytes == secret_bytes


def test_payload_binary_serialization():
    secret = "Steganography Stream Verification"
    passphrase = "CarrierPassphrase"

    payload = encrypt(secret, passphrase)
    stream = payload.to_bytes()
    assert stream.startswith(b"STG1")

    # Deserialize and decrypt from raw bytes stream
    decrypted = decrypt(stream, passphrase)
    assert decrypted == secret


def test_payload_base64_serialization():
    secret = "Base64 Web/JSON Payload"
    passphrase = "WebClientPassphrase"

    payload = encrypt(secret, passphrase)
    b64_str = payload.to_base64()

    reconstructed = EncryptedPayload.from_base64(b64_str)
    assert reconstructed.salt == payload.salt
    assert reconstructed.nonce == payload.nonce
    assert reconstructed.ciphertext == payload.ciphertext

    decrypted = decrypt(b64_str, passphrase)
    assert decrypted == secret


def test_decrypt_wrong_passphrase_raises():
    secret = "Bank vault combinations: 88-12-44"
    passphrase = "CorrectMasterKey"
    wrong_passphrase = "WrongMasterKey"

    payload = encrypt(secret, passphrase)
    with pytest.raises(DecryptionError, match="Authentication tag verification failed"):
        decrypt(payload, wrong_passphrase)


def test_decrypt_tampered_ciphertext_raises():
    secret = "Tamper check payload"
    passphrase = "IntegrityPassphrase"

    payload = encrypt(secret, passphrase)
    tampered_bytes = bytearray(payload.to_bytes())
    tampered_bytes[-1] ^= 0x01  # Alter ciphertext tag byte

    with pytest.raises(DecryptionError, match="Authentication tag verification failed"):
        decrypt(bytes(tampered_bytes), passphrase)


def test_raw_32byte_key_mode():
    secret = "Direct symmetric key test"
    raw_key = os.urandom(32)

    payload = encrypt(secret, raw_key)
    assert payload.salt == b""

    decrypted = decrypt(payload, raw_key)
    assert decrypted == secret


def test_corrupted_magic_header():
    corrupted_data = b"BAD1" + os.urandom(40)
    with pytest.raises(CorruptedDataError, match="Invalid payload magic header"):
        EncryptedPayload.from_bytes(corrupted_data)
