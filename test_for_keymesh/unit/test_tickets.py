import dataclasses

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keymesh_common.tickets import SignedTicket, TicketError, TicketIssuer, TicketVerifier

# The tests use a fixed time value
# This makes the tests predictable and reproducible
NOW = 1_800_000_000


@pytest.fixture
def pair():
    sk = Ed25519PrivateKey.generate()   # Create a new Ed25519 private key for signing tickets

    # TicketIssuer signs tickets using a private key
    # TicketVerifier verifies them using a public key
    return TicketIssuer(sk, ttl_seconds=30), TicketVerifier(sk.public_key())


def test_valid_ticket_accepted(pair):
    # Verify that a valid ticket is accepted
    issuer, verifier = pair
    
    # Create a request for user u1 and record rec-1
    t = issuer.issue("u1", "rec-1", epoch=3, now=NOW)
    
    # Check your ticket in a second
    assert verifier.verify(t, record_id="rec-1", current_epoch=3, now=NOW + 1).user_id == "u1"


def test_encode_decode_round_trip(pair):
    # Verify that a ticket can be encoded into a string
    # and decoded back without being corrupted
    issuer, verifier = pair
    
    token = issuer.issue("u1", "rec-1", 3, now=NOW).encode()
    
    # Decode the token and verify it again
    verifier.verify(SignedTicket.decode(token), record_id="rec-1", current_epoch=3, now=NOW)


@pytest.mark.parametrize("kwargs,reason", [
    ({"record_id": "rec-2", "current_epoch": 3, "now": NOW}, "wrong_record"),
    ({"record_id": "rec-1", "current_epoch": 4, "now": NOW}, "wrong_epoch"),
    ({"record_id": "rec-1", "current_epoch": 3, "now": NOW + 30}, "expired"),
])


def test_rejections(pair, kwargs, reason):
    # Check the various reasons why an application might be rejected
    issuer, verifier = pair
    
    t = issuer.issue("u1", "rec-1", 3, now=NOW)
    
    # The check should fail
    with pytest.raises(TicketError) as err:
        verifier.verify(t, **kwargs)
    # Verify that the correct rejection reason is returned
    assert err.value.reason == reason


def test_replay_rejected(pair):
    # Verify that the same ticket cannot be used twice
    issuer, verifier = pair

    t = issuer.issue("u1", "rec-1", 3, now=NOW)

    # The first use should work
    verifier.verify(t, record_id="rec-1", current_epoch=3, now=NOW)
    
    # Reusing the same ticket must be rejected
    with pytest.raises(TicketError, match="replayed"):
        verifier.verify(t, record_id="rec-1", current_epoch=3, now=NOW + 1)


def test_modified_ticket_rejected(pair):
    # Verify that modifying the ticket data invalidates the signature
    issuer, verifier = pair

    t = issuer.issue("u1", "rec-1", 3, now=NOW)

    # Change the record identifier, but keep the old signature
    forged = SignedTicket(dataclasses.replace(t.ticket, record_id="rec-9"), t.signature)
    # The modified request must fail the signature check
    with pytest.raises(TicketError, match="bad_signature"):
        verifier.verify(forged, record_id="rec-9", current_epoch=3, now=NOW)


def test_ticket_from_other_issuer_rejected(pair):
    # Verify that a ticket signed with a different key is rejected
    _, verifier = pair
    
    # Create another issuer with a different private key
    rogue = TicketIssuer(Ed25519PrivateKey.generate()).issue("u1", "rec-1", 3, now=NOW)
    
    # Our verifier must not trust this ticket
    with pytest.raises(TicketError, match="bad_signature"):
        verifier.verify(rogue, record_id="rec-1", current_epoch=3, now=NOW)
