"""Week 1. Create endpoints <the real end points will be add later >"""
import os
from fastapi import FastAPI

# Name of this microservice
SERVICE_NAME = "api_gateway"

# Creating a FastAPI application
app = FastAPI(title=SERVICE_NAME)

@app.get("/health")
def health() ->dict:
    # A simple check of whether a service is running
    return {"service": SERVICE_NAME, "instance": os.getenv("INSTANCE_ID","1"), "status": "ok"}

