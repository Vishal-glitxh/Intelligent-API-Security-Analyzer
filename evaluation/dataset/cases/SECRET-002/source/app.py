import os
from fastapi import FastAPI

app = FastAPI()

API_KEY = os.getenv("API_KEY")

@app.get("/api/v1/status")
def status():
    return {"status": "online"}
