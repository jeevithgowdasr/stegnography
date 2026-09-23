"""Unit tests for Cryptography components (AES-256-GCM and PBKDF2)."""

import pytest
from image_stego.crypto.kdf import derive_key, generate_salt
from image_stego.crypto.encryptor import encrypt_data, decrypt_data
from image_stego.core.exceptions import DecryptionError


def test_kdf_derivation():
    password = "SuperSecretPassword123!"
    salt1 = generate_salt(16)
    salt2 = generate_salt(16)

    key1 = derive_key(password, salt1)
    key2 = derive_key(password, salt1)
    key3 = derive_key(password, salt2)

    assert len(key1) == 32  # 256 bits
    assert key1 == key2     # Deterministic for same salt
    assert key1 != key3     # Different salts yield different keys


def test_kdf_empty_password():
    salt = generate_salt()
    with pytest.raises(ValueError, match="Password cannot be empty"):
        derive_key("", salt)


def test_encrypt_decrypt_roundtrip():
    secret_message = b"Top secret operational intelligence for eyes only."
    password = "CorrectHorseBatteryStaple42#"

    ciphertext, salt, nonce = encrypt_data(secret_message, password)

    assert ciphertext != secret_message
    assert len(salt) == 16
    assert len(nonce) == 12

    decrypted = decrypt_data(ciphertext, password, salt, nonce)
    assert decrypted == secret_message


def test_decrypt_with_wrong_password():
    secret_message = b"Classified military coordinate data."
    password = "RealPassword2026"
    wrong_password = "AttackerGuessedPassword"

    ciphertext, salt, nonce = encrypt_data(secret_message, password)

    with pytest.raises(DecryptionError, match="Authentication failed"):
        decrypt_data(ciphertext, wrong_password, salt, nonce)


def test_decrypt_tampered_ciphertext():
    secret_message = b"Transfer $1,000,000 to Account #9942"
    password = "BankingMasterKey"

    ciphertext, salt, nonce = encrypt_data(secret_message, password)

    # Flip one byte in ciphertext
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01
    tampered_bytes = bytes(tampered)

    with pytest.raises(DecryptionError, match="Authentication failed"):
        decrypt_data(tampered_bytes, password, salt, nonce)
