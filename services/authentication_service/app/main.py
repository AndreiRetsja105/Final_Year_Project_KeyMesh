"""Week 1 Authentification service [the real endpoints will be connected later ]"""
import os

from fastapi import FastAPI

# Name of this microservice
SERVICE_NAME = "authentication_service"
# Creating a FastAPI applicationa
app = FastAPI(title=SERVICE_NAME)

@app.get("/health")
def health() ->dict:
    # A simple check of whether a service is running
    return {"service": SERVICE_NAME, "instance": os.getenv("INSTANCE_ID", "1"), "status": "ok"}
    
