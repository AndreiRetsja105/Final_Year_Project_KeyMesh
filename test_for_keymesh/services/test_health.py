"""Smoke test: every service must correctly import its dependencies and respond via the `/health` endpoint.
This helps identify typos (such as missing imports or incorrect names) even before the Docker image is built."""
import importlib.util
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Path to the folder where all microservices are stored
SERVICES = Path(__file__).resolve().parents[2] / "services"

# List of services to check
NAMES = ["api_gateway", "authentication_service", "data_service", "crypto_service", "key_service"]


def load_app(name: str):
    # Find main.py for the selected service
    service_file = SERVICES / name / "app" / "main.py"

    # Load a service module directly from its file
    spec = importlib.util.spec_from_file_location(f"{name}_main", SERVICES / name / "app" / "main.py")
    
    module = importlib.util.module_from_spec(spec)
    
    # Run the module to access its FastAPI application
    spec.loader.exec_module(module)
    return module.app


@pytest.mark.parametrize("name", NAMES)
def test_health(name):

    # Load each service and call its /health endpoint
    response = TestClient(load_app(name)).get("/health")
    
    # The service must respond successfully
    assert response.status_code == 200

    # Every service must return status = ok
    assert response.json()["status"] == "ok"


def test_key_service_refuses_when_not_provisioned():
    # The Key Service must not issue a share
    # if it does not possess the necessary share or ticket verifier:
    response = TestClient(load_app("key_service")).post(
        "/shares/release", json={"ticket": "x.y", "record_id": "rec-1"})
    # The service should return 503, as it is not prepared for operation
    assert response.status_code == 503
