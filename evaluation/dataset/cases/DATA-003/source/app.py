from fastapi import FastAPI

app = FastAPI()

@app.get("/api/v1/public_key")
def get_public_key():
    return {"public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."}
