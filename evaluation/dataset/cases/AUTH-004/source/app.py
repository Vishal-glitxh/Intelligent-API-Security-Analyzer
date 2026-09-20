from fastapi import FastAPI

app = FastAPI()

@app.get("/api/v1/public/ping")
def public_ping():
    return {"pong": True}
