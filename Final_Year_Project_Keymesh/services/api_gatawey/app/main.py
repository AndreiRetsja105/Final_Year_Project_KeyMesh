"""Week 1. Create endpoints <the real end points will be add later >"""

from fastapi import FastAPI

SERVICE_NAME = "api_gateway"
app = FastAPI(title=SERVICE_NAME)

@app.get("/health")
def health() ->dict:
    return {"service": SERVICE_NAME, "instance": os.getenv("INSTANCE_ID","1"), "status": "ok"}

