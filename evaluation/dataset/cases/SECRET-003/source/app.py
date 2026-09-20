from fastapi import FastAPI

app = FastAPI()

API_KEY_PLACEHOLDER = "YOUR_API_KEY_HERE"

@app.get("/api/v1/status")
def status():
    return {"status": "online"}
