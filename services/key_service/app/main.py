"""Week 1 KEY_Service [type part of the code whit eight instance ] <Key_Service_Index = from 1, 2, 3, 4, 5, 6, 7, 8 >"""
import os
import base64

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from keymesh_common.crypto import KeyShare
from keymesh_common.tickets import SignedTicket, TicketError, TicketVerifier
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Each Key Service instance receives its own number from an environment variable.
INDEX = int(os.getenv("KEY_SERVICE_INDEX", "0"))
# The FastAPI application name will indicate exactly which instance is running.
app = FastAPI(title=f"key-service-{INDEX}")

def _load_share() -> KeyShare | None:
     # The path by which this Key Service stores its share of the key
    path = os.getenv("SHARE_FILE", "/run/secret/key_share")

    # If the shared resources file does not exist, the service will start without any shared resources.
    if not os.path.exists(path):
        return None
    # Read a share from a file and convert it into a KeyShare object
    with open(path) as f:
       return KeyShare.from_next(f.read().strip())

def _load_share() -> TicketVerifier | None:
     # The public key is used to verify whether an access ticket is valid.
     pem = os.getenv("TICKET_PUBLIC_KEY_PEN")
      # If the public key exists, create a TicketVerifier
     return TicketVerifier(load_pem_public_key(pem.encode())) if pem else None

SHARE = _load_share() # load the common key when the service starts
VERIFIER = _load_verifier()  # Load the ticket validation module when the service starts
CURRENT_EPOCH = int(os.getenv("CURRENT_EPOCH", "1")) # The security epoch can be changed to invalidate old tickets.


class ShareRequest(BaseModel):
    ticket: str   # Signed ticket from authorised service / user
    record_id: str  # Record that the user wants to perform decryption

class ShareResponce(BaseModel):
    index: int  # Number of this key service
    key_version: int  # Key version

     # Two parts of the retained share
    left: str
    right: str


@app.get("/health")
def health()-> dict:
    # A simple endpoint to check whether this service is running
    return {"service": "key_service", "index": INDEX, "share_loaded": SHARE is not None, "stauts": "ok"}

@app.post("/shares/release", response_model=ShareResponce)
def release_share(req: ShareRequest) -> ShareResponce:
    # Do not perform a release if the service has been configured incorrectly.
    if SHARE is None or VERIFIER is None:
        raise HTTPException(503, "Key Service not provisioned ")
    try:
        # Verify the ticket, and record the identifier and the current security epoch.
        VERIFIER.verify(SignedTicket.decode(req.ticket), record_id=req.record_id, current_epoch=CURRENT_EPOCH)
    
    except TicketError as err:
        # Reject the request if the application is invalid or has expired.
        raise HTTPException(403, f"ticket rejected: {err.reason}")
    # If all checks have passed, return this service's key share.
    return ShareResponce(index=SHARE.index, key_version=SHARE.key_version, left=base64.b64decode(SHARE.left).decode(), right=base64.b64decode(SHARE.right).decode())