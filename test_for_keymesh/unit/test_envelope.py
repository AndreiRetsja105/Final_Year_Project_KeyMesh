import dataclasses

import pytest

from keymesh_common.crypto import AesGcmCipher, DecryptionError, EnvelopeEncryptor


@pytest.fixture
def master_key():
    # Create a new master key for tests
    return AesGcmCipher.generate_key()


def test_round_trip(master_key):
    # Verify that the data can be encrypted and then correctly decrypted back
    env = EnvelopeEncryptor()
    rec = env.encrypt("rec-1", b"synthetic patient record", master_key)
    assert env.decrypt(rec, master_key) == b"synthetic patient record"


def test_each_record_gets_distinct_dek(master_key):
    
    # Even if records contain identical data,
    # the same encryption result should not be used for them
    env = EnvelopeEncryptor()
    
    a = env.encrypt("rec-1", b"same", master_key)
    b = env.encrypt("rec-2", b"same", master_key)
    
    # The encrypted data and the wrapped DEK must be different
    assert a.ciphertext != b.ciphertext and a.wrapped_dek != b.wrapped_dek


@pytest.mark.parametrize("field", ["ciphertext", "wrapped_dek"])
def test_tampering_is_detected(master_key, field):

    # Verify that modification of encrypted data is detected
    env = EnvelopeEncryptor()
    rec = env.encrypt("rec-1", b"data", master_key)
    
    # Modify a single byte in the ciphertext or the wrapped DEK
    value = bytearray(getattr(rec, field)); value[0] ^= 1
    
    # Decryption must fail after data modification
    with pytest.raises(DecryptionError):
        env.decrypt(dataclasses.replace(rec, **{field: bytes(value)}), master_key)


def test_ciphertext_moved_to_other_record_is_rejected(master_key):
    # Verify that encrypted data from one record
    # cannot simply be moved to another record (with a different identifier)
    env = EnvelopeEncryptor()
    
    rec = env.encrypt("rec-1", b"data", master_key)
    # Change the record identifier, but keep the same encrypted data
    with pytest.raises(DecryptionError):
        env.decrypt(dataclasses.replace(rec, record_id="rec-2"), master_key)


def test_wrong_master_key_fails(master_key):
    # Verify that decryption fails if a different master key is used
    env = EnvelopeEncryptor()
    rec = env.encrypt("rec-1", b"data", master_key)
    # Generate another key and try performing the decryption using it
    with pytest.raises(DecryptionError):
        env.decrypt(rec, AesGcmCipher.generate_key())
