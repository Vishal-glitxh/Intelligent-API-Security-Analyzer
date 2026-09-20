from fastapi import FastAPI

app = FastAPI()

TEST_DB_PASSWORD = "test_password_123"

@app.get("/api/v1/status")
def status():
    return {"status": "online"}
