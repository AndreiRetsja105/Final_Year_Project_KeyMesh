"""Week 1 DATA service [the real endpoints will be added later ]"""

import os

from fastapi import FastAPI

# Name of this microservice
SERVICE_NAME = "data_service"
# Creating a FastAPI application
app = FastAPI(title=SERVICE_NAME)

@app.get("/health")
def health() -> dict:
    # A simple check of whether a service is running
    return{"service": SERVICE_NAME, "instance": os.getenv("INSTANCE_ID", "1"), "status": "ok"}
