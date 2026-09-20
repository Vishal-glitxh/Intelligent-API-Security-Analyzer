from fastapi import FastAPI

app = FastAPI()

# Controlled benchmark fake key for static analysis detection
AWS_SECRET_KEY = "AKIAIOSFODNN7NOTREAL"

@app.get("/api/v1/status")
def status():
    return {"status": "online"}

