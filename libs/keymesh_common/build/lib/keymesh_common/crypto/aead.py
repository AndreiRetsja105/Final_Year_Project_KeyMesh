"""Thin wrapper around AES-256-GCM (NIST SP 800-38D)."""
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32    # 256-bit key
NONCE_SIZE = 12  # 96-bit nonce, recommended for GCM


class DecryptionError(Exception):
    """Ciphertext, nonce or associated data was modified, or the key is wrong."""


class AesGcmCipher:
    def __init__(self, key: bytes) -> None:
        if len(key) != KEY_SIZE:
            raise ValueError("AES-256-GCM requires a 32-byte key")
        self._aead = AESGCM(key)

    @staticmethod
    def generate_key() -> bytes:
        return AESGCM.generate_key(bit_length=256)

    def encrypt(self, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
        nonce = os.urandom(NONCE_SIZE)
        return nonce, self._aead.encrypt(nonce, plaintext, aad)

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        try:
            return self._aead.decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise DecryptionError("authentication tag check failed") from exc
