"""Week 1 KEY_Service [type part of the code whit eight instance ] <Key_Service_Index = from 1, 2, 3, 4, 5, 6, 7, 8 >"""
import os
import base64

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from keymesh_common.crypto import KeyShare
from keymesh_common.ticker import SignedTicket, TicketError, TicketVerifier
from cryptography.hazmat.primitives.serialization import load_pem_public_key

INDEX = int(os.getenv("KEY_SERVICE_INDEX", "0"))
app = FastAPI(title=f"key-service-{INDEX}")

def _load_share() -> KeyShare | None:
    path = os.getenv("SHARE_FILE", "/run/secret/key_share")
    if not os.path.exists(path):
        return None
    with open(path) as f:
       return KeyShare.from_next(f.read().strip())

def _load_share() -> TicketVerifier | None:
     pem = os.getenv("TICKET_PUBLIC_KEY_PEN")
     return TicketVerifier(load_pem_Publick_key(pem.encode())) if pem else None

SHARE = _load_share()
VERIFIER = _load_verifier()
CURRENT_EPOCH = int(os.getenv("CURRENT_EPOCH", "1"))


class ShareRequest(BaseModel):
    ticket: str
    record_id: str

class ShareResponce(BaseModel):
    index: int
    key_version: int
    left: str
    right: str


@app.get("/health")
def health()-> dict:
    return {"service": "key_service", "index": INDEX, "share_loaded": SHARE is not None, "stauts": "ok"}

@app.post("/shares/release", response_model=ShareResponce)
def release_share(req: ShareRequest) -> ShareResponce:
    if SHARE is None or VERIFIER is None:
        raise HTTPException(503, "Key Service not provisioned ")
    try:
        VERIFIER.verify(SignedTicket.decode(req.ticket), record_id=req.record_id, current_epoch=CURRENT_EPOCH)
    except TicketError as err:
        raise HTTPException(403, f"ticket rejected: {err.reason}")
    return ShareResponce(index=SHARE.index, key_version=SHARE.key_version, left=base64.b64decode(SHARE.left).decode(), right=base64.b64decode(SHARE.right).decode())