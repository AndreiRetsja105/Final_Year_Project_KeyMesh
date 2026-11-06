"""Short lived, one time use decryption tickets, signed using the Ed25519 algorithm

such a ticket is created by the Authentication Service (Auth Service)
each Key service validates the ticket before providing its portion of the key """

import base64
import json
import secrets
import time
from dataclasses import asdict, dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (Ed25519PrivateKey, Ed25519PublicKey,)

class TicketError(Exception):
    """" The request was rejected, and the reason can be recorded in the audit log """
    
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class DecryptionTicket:
    # string a unique identifier makes each ticket distinct from the others
    ticket_id: str  # one time nonce 
    
    # string user who requested access
    user_id: str
    
    # string the record that the user wants to perform decryption
    record_id: str
    
    # integer for the current Era of security
    epoch: int 
    
    # integer for request creation time
    issued_at: int
    
    # integer for time after which a ticket becomes invalid
    expires_at: int 

    def payload(self) -> bytes:
        # convertitng the ticket data into the same byte format, every single time
        # this is essential for creating and verifying the signature
        return json.dumps(asdict(self), sort_keys=True, separators=(",",":")).encode()

    
@dataclass(frozen=True)
class SignedTicket:
    # information about the original application
    ticket: DecryptionTicket
    
    # Ed25519 signature
    signature: bytes

    def encode(self) -> str:
        # converting the ticket and signature into a string
        # so that they can be passed between services
        body = base64.urlsafe_b64encode(self.ticket.payload()).decode()
        sig = base64.urlsafe_b64encode(self.signature).decode()
        return f"{body}.{sig}"

    @classmethod
    def decode(cls, token: str) -> "SignedTicket":
        # converting a string token back into a signed Ticket object
        try:
            body, sig = token.split(".")
            data = json.loads(base64.urlsafe_b64decode(body))
            
            return cls(DecryptionTicket(**data), base64.urlsafe_b64decode(sig))
        
        except Exception as exc:
            # rejecting the request if the token format is invalid
            raise TicketError("malformed") from exc

        
class TicketIssuer:
    def __init__ (self, private_key: Ed25519PrivateKey, ttl_seconds: int= 30) -> None:
        
        # the row wich using a private key wich is used only for signing tickets
        self._key = private_key

        # the ticket will be valid only for a short time
        self._ttl = ttl_seconds

    def issue(self, user_id: str, record_id:str, epoch: int, now: int | None = None) -> SignedTicket:

        # using the current time if no fixed time is specified in the test
        now = int(time.time()) if now is None else now 

        # creating a new single-use ticket
        ticket = DecryptionTicket(secrets.token_hex(16), user_id, record_id, epoch, now, now + self._ttl)
            
        return SignedTicket(ticket, self._key.sign(ticket.payload())) 


class ReplayCache:
    """IA repository of used tickets held in RAM.
    each key service maintains its own repository; 
    entries can be removed once they expire"""

    def __init__(self) -> None:

        # ticket identifier -> expiration time
        self._seen: dict[str, int] = {}

    def check_and_add(self, ticket_id: str, expires_at: int, now: int) -> bool:

        # it remove old, expired tickets from memory
        self._seen = {k: v for k, v in self._seen.items() if v >= now}
        
        # the ticket has already been used
        if ticket_id in self._seen:
            return False

        # remember this ticket so that it cannot be used again
        self._seen[ticket_id] = expires_at
        
        return True


class TicketVerifier:
    def __init__(self, public_key: Ed25519PublicKey, replay_cache: ReplayCache | None = None) -> None:
        
        # the public key verifies signatures created by the authentication service (Auth Service)
        self._key = public_key

        # each verifier tracks used tickets
        self._replay = replay_cache or ReplayCache()

    def verify(self, signed: SignedTicket, *, record_id: str, current_epoch: int, now: int | None = None) -> DecryptionTicket:
        
        # using the current real-time if the test does not provide it.
        now = int(time.time()) if now is None else now
        t = signed.ticket
        try:
            # first, verify that the authentication service actually signed this ticket
            self._key.verify(signed.signature, t.payload())
        except InvalidSignature as exc:
            raise TicketError("bad_signature") from exc
        
        # the ticket cannot be used after its expiration date
        if now >= t.expires_at:
            raise TicketError("expired")
        
        # the ticket should apply only to the corresponding record
        if t.record_id != record_id:
            raise TicketError("wrong_record")
        
        # an old epoch means that old access rights should no longer work
        if t.epoch != current_epoch:
            raise TicketError("wrong_epoch")
        
        # the ticket is for one-time use only; therefore, any attempt to reuse it must be rejected.
        if not self._replay.check_and_add(t.ticket_id, t.expires_at, now):
            raise TicketError("replayed")

        # all checks passed
        return t