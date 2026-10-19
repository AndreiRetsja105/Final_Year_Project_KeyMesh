import itertools
import random

import pytest

from keymesh_common.crypto import AesGcmCipher, DecryptionError, EnvelopeEncryptor, KeyShare, ShamirKeySplitter


@pytest.fixture
def setup():
    # Create one random master key for testing
    key = AesGcmCipher.generate_key()

    # Shamir configuration: 5 out of 8 shares required
    splitter = ShamirKeySplitter(5, 8)
    return key, splitter, splitter.split(key)


def test_eight_shares_created(setup):
    # Verify that exactly 8 shares have been created
    _, _, shares = setup

    # Share indices must be in the range from 1 to 8
    assert sorted(s.index for s in shares) == list(range(1, 9))


def test_any_five_of_eight_reconstruct(setup):
    # Verify that any group of 5 shares allows for the reconstruction of the original key
    key, splitter, shares = setup
    # Test all possible groups of 5 stocks out of 8
    for combo in itertools.combinations(shares, 5):   # all 56 combinations
        assert splitter.combine(list(combo)) == key


def test_four_shares_are_refused(setup):
    # Four shares should not be sufficient to reconstruct the key
    _, splitter, shares = setup
    
    with pytest.raises(ValueError):
        splitter.combine(shares[:4])


def test_four_shares_plus_forged_cannot_decrypt(setup):
    """An attacker possesses 4 actual shares and correctly guesses a 5th; 
    the resulting reconstruction yields an incorrect key, 
    which is detected via the GCM tag on the encrypted Data Encryption Key (DEK)."""
    
    # Let’s model an attacker who possesses 4 genuine shares
    # and attempts to create a fake fifth share
    key, splitter, shares = setup

    # Encrypt some test data using the actual master key
    record = EnvelopeEncryptor().encrypt("rec-1", b"secret", key)
    
    # Create a dummy shared resource with random data
    forged = KeyShare(shares[4].index, random.randbytes(16), random.randbytes(16))
    
    # Combine 4 genuine promotions with one fake one
    wrong = splitter.combine(shares[:4] + [forged])

    # The recovered key must not match the actual master key
    assert wrong != key
    
    # Decryption should fail, as the key is incorrect
    with pytest.raises(DecryptionError):
        EnvelopeEncryptor().decrypt(record, wrong)


def test_duplicate_shares_do_not_count(setup):
    # Verify that using the same share twice does not help reach the threshold value
    _, splitter, shares = setup
    # 4 genuine shares + a duplicate of the first share must be rejected
    with pytest.raises(ValueError):
        splitter.combine(shares[:4] + [shares[0]])


def test_hex_round_trip(setup):
    # Verify that the fraction can be converted to hexadecimal format
    # and then correctly restored back
    _, _, shares = setup
    assert KeyShare.from_hex(shares[0].to_hex()) == shares[0]
