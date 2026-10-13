"""Week 1 crypto service [the real endpoints will be added later ]"""

import os

from fastapi import FastAPI

SERVICE_NAME = "crypto_service"
app = FastAPI(title=SERVICE_NAME)

@app.get("/health")
def health() -> dict:
    return{"service": SERVICE_NAME, "instance": os.getenv("INSTANCE_ID", "1"), "status": "ok"}
