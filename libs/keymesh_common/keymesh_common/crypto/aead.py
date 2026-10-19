"""Thin wrapper around AES-256-GCM (NIST SP 800-38D)."""
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AES-256 uses a 32-byte key
KEY_SIZE = 32    # 256-bit key

# GCM usually uses a 12-byte nonce
NONCE_SIZE = 12  # 96-bit nonce, for GCM


class DecryptionError(Exception):
    """ The ciphertext, nonce, or associated data have been modified, or the key is incorrect """


class AesGcmCipher:
    def __init__(self, key: bytes) -> None:
        # Ensure that the key is the correct size for AES-256
        if len(key) != KEY_SIZE:
            raise ValueError("AES-256-GCM requires a 32-byte key")
        
        # Create an AES-GCM object with this key
        self._aead = AESGCM(key)

    @staticmethod
    def generate_key() -> bytes:

        # Generate a new random 256-bit AES key
        return AESGCM.generate_key(bit_length=256)

    def encrypt(self, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:

        # For each encryption, generate a new random nonce (number used once)
        nonce = os.urandom(NONCE_SIZE)

        # Encrypt the data and return a nonce along with the ciphertext
        ciphertext = self._aead.encrypt(nonce, plaintext,aad)
                
        return nonce, self._aead.encrypt(nonce, plaintext, aad)

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        try:
            # Decrypt the data and verify its authentication tag
            return self._aead.decrypt(nonce, ciphertext, aad)
        
        except InvalidTag as exc:
            # An incorrect key or altered encrypted data will lead to this result
            raise DecryptionError("authentication tag check failed") from exc
