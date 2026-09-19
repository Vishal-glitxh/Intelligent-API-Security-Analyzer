# FastAPI vulnerable fixture for static security analysis
from fastapi import FastAPI

app = FastAPI()

# Hardcoded secret
API_KEY = "sk_live_998877665544332211"


# API-SOURCE-AUTH-001: Unauthenticated POST endpoint
@app.post("/items")
async def create_item(payload: dict):
    return {"created": True}


# API-SOURCE-AUTHZ-001: Object lookup using path parameter without authorization check
@app.get("/users/{user_id}")
async def get_user(user_id: str):
    # Resource lookup without ownership or role verification
    user = db.get("User", user_id)
    return user
