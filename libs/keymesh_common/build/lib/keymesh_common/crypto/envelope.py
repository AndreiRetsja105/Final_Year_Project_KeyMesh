"""Envelope encryption: each record gets its own data key (DEK),
the DEK is wrapped under the master key (KEK), which exists only as Shamir shares."""
from dataclasses import dataclass

from .aead import AesGcmCipher


@dataclass(frozen=True)
class EncryptedRecord:
    record_id: str
    key_version: int        # which master key wrapped the DEK
    data_nonce: bytes
    ciphertext: bytes
    dek_nonce: bytes
    wrapped_dek: bytes


class EnvelopeEncryptor:
    @staticmethod
    def _dek_aad(record_id: str, key_version: int) -> bytes:
        return f"keymesh:dek:{record_id}:v{key_version}".encode()

    @staticmethod
    def _data_aad(record_id: str) -> bytes:
        return f"keymesh:record:{record_id}".encode()

    def encrypt(self, record_id: str, plaintext: bytes,
                master_key: bytes, key_version: int = 1) -> EncryptedRecord:
        dek = AesGcmCipher.generate_key()
        data_nonce, ciphertext = AesGcmCipher(dek).encrypt(plaintext, self._data_aad(record_id))
        dek_nonce, wrapped = AesGcmCipher(master_key).encrypt(
            dek, self._dek_aad(record_id, key_version))
        return EncryptedRecord(record_id, key_version, data_nonce, ciphertext, dek_nonce, wrapped)

    def decrypt(self, record: EncryptedRecord, master_key: bytes) -> bytes:
        dek = AesGcmCipher(master_key).decrypt(
            record.dek_nonce, record.wrapped_dek,
            self._dek_aad(record.record_id, record.key_version))
        return AesGcmCipher(dek).decrypt(
            record.data_nonce, record.ciphertext, self._data_aad(record.record_id))
