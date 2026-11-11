"""test for a provisioned key services: share file present and a ticket verified configuration"""

"""the smoke test only check the not provisioned case 503. this test check the success path, so a service that silently fails to load its share is cough  """

import base64
import importlib.util
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from keymesh_common.crypto import (AesGcmCipher, EnvelopeEncryptor, KeyShare, ShamirKeySplitter)
from keymesh_common.tickets import TicketIssuer

KEY_SERVICE_FILE = Path(__file__).resolve().parents[2] / "services" / "key_service" / "app" / "main.py"

def public_pem(private_key) -> str:
    return private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

@pytest.fixture
def world(tmp_path):
    """ a master key , it is 8 shares written to files, and a ticket signing key"""
    master = AesGcmCipher.generate_key()
    shares = ShamirKeySplitter(5, 8).split(master)
    for s in shares:
        (tmp_path / f"share_{s.index}.txt").write_text(s.to_hex())
    signing_key = Ed25519PrivateKey.generate()
    return {"master": master, "dir": tmp_path, "sk": signing_key, "issuer": TicketIssuer(signing_key, ttl_seconds=30)}


def start_service(monkeypatch, world, index, epoch="1", shaere_exist=True, pem=None):
    """"important key_service/app/main.py with the enviroment of one instance """
    share_path = world["dir"] / (f"share_{index}.txt" if shaere_exist else "mising.txt")
    monkeypatch.setenv("KEY_SERVICE_INDEX", str(index))
    monkeypatch.setenv("CURRENT_EPOCH", epoch)
    monkeypatch.setenv("SHARE_FILE", str(share_path))
    monkeypatch.setenv("TICKET_PUBLIC_KEY_PEM", pem if pem is not None else public_pem(world["sk"]))
    spec = importlib.util.spec_from_file_location(f"key_service_{index}_{epoch}", KEY_SERVICE_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return TestClient(module.app)


def test_share_loaded_when_file_exists(monkeypatch, world):
    client = start_service(monkeypatch, world, 1)
    assert client.get("/health").json()["share_loaded"] is True


def test_share_not_loaded_when_file_missing(monkeypatch, world):
    client = start_service(monkeypatch, world, 1, shaere_exist=False)
    assert client.get("/health").json()["share_loaded"] is False


def test_valid_ticket_releases_share_and_five_decrypt(monkeypatch, world):
    record = EnvelopeEncryptor().encrypt("rec-1", b"synthetic record", world["master"])
    token = world["issuer"].issue("ul", "rec-1", epoch=1).encode()

    collected =[]
    for index in range(1, 6):   # five difirent key services 
        client = start_service(monkeypatch, world, index)
        response = client.post("/shares/release", json={"ticket": token, "record_id": "rec-1"})
        assert response.status_code == 200
        body = response.json()
        collected.append(KeyShare(body["index"], base64.b64decode(body["left"]), base64.b64decode(body["right"]), body["key_version"]))

    key = ShamirKeySplitter(5, 8).combine(collected)
    assert EnvelopeEncryptor().decrypt(record, key) == b"synthetic record"


def test_replayed_ticket_is_refused(monkeypatch, world):
    client = start_service(monkeypatch, world, 1)
    token = world["issuer"].issue("ul", "rec-1", epoch=1).encode()
    first = client.post("/shares/release", json={"ticket": token, "record_id": "rec-1"})
    second = client.post("/shares/release", json={"ticket": token, "record_id": "rec-1"})
    assert first.status_code == 200
    assert second.status_code == 403 and "replayed" in second.json()["detail"]


def test_ticket_for_another_record_is_refused(monkeypatch, world):
    client = start_service(monkeypatch, world, 1)
    token = world["issuer"].issue("ul", "rec-1", epoch=1).encode()
    response = client.post("/shares/release", json={"ticket": token, "record_id": "rec-2"})
    assert response.status_code == 403 and "wrong_record" in response.json()["detail"]


def test_old_epoch_ticket_is_refused(monkeypatch, world):
    client = start_service(monkeypatch, world, 1, epoch="2")
    token = world["issuer"].issue("u1", "rec-1", epoch=1).encode()
    response = client.post("/shares/release", json={"ticket": token, "record_id": "rec-1"})
    assert response.status_code == 403 and "wrong_epoch" in response.json()["detail"]


def test_ticket_signed_by_unknow_key_is_refused(monkeypatch, world):
    client = start_service(monkeypatch, world, 1)
    rogue = TicketIssuer(Ed25519PrivateKey.generate()).issue("ul", "rec-1", epoch=1).encode()
    response = client.post("/shares/release", json={"ticket": rogue, "record_id": "rec-1"})
    assert response. status_code == 403 and "bad_signature" in response.json()["detail"]

