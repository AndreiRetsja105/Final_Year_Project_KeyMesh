"""Week 1 Authentification service [the real endpoints will be connected later ]"""
import os

from fastapi import FastAPI

SERVICE_NAME = "authentification_service"
app = FastAPI(title=SERVICE_NAME)

@app.get("/health")
def health() ->dict:
    return {"service": SERVICE_NAME, "instance": os.getenv("INSTANCE_ID", "1"), "status": "ok"}
    
