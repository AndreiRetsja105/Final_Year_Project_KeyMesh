""" Envelope encryption: for each record, a unique data 
encryption key (DEK) is created, which is then encrypted using 
a key encryption key (KEK) that exists solely in the form of 
shares based on Shamir’s scheme """

from dataclasses import dataclass

from .aead import AesGcmCipher


@dataclass(frozen=True)
class EncryptedRecord:
    # Encrypted record identifier
    record_id: str
    
    # Shows which version of the master key was used
    key_version: int        # which master key wrapped the DEK
    
     # Nonce used to encrypt the actual record data
    data_nonce: bytes
    
    # Encrypted record data
    ciphertext: bytes
    
    # Nonce used when encrypting the DEK
    dek_nonce: bytes
    
    # DEK encrypted with the master key
    wrapped_dek: bytes


class EnvelopeEncryptor:
    @staticmethod
    def _dek_aad(record_id: str, key_version: int) -> bytes:
        # Additional authenticated data for the wrapped DEK
        # This binds the DEK to the given record and key version
        return f"keymesh:dek:{record_id}:v{key_version}".encode()

    @staticmethod
    def _data_aad(record_id: str) -> bytes:
        # Additional authenticated data for the record itself
        # This binds the encrypted data to a specific record identifier
        return f"keymesh:record:{record_id}".encode()

    def encrypt(self, record_id: str, plaintext: bytes, master_key: bytes, key_version: int = 1) -> EncryptedRecord:
        # Create a new random DEK for this record
        dek = AesGcmCipher.generate_key()
        
        # Encryption of the record itself using its own DEK
        data_nonce, ciphertext = AesGcmCipher(dek).encrypt(plaintext, self._data_aad(record_id))
        
        # Encrypt the DEK using a master key
        dek_nonce, wrapped = AesGcmCipher(master_key).encrypt(
            dek, self._dek_aad(record_id, key_version))

        # Save everything necessary for subsequent transcription
        return EncryptedRecord(record_id, key_version, data_nonce, ciphertext, dek_nonce, wrapped)

    def decrypt(self, record: EncryptedRecord, master_key: bytes) -> bytes:
        # First, decrypt the DEK using the master key
        dek = AesGcmCipher(master_key).decrypt(
            record.dek_nonce, record.wrapped_dek,
            self._dek_aad(record.record_id, record.key_version))
        
        # Then use the DEK to decrypt the record itself
        return AesGcmCipher(dek).decrypt(
            record.data_nonce, record.ciphertext, self._data_aad(record.record_id))
