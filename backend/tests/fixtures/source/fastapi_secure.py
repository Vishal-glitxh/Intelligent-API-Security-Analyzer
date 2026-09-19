# FastAPI secure fixture for static security analysis
import os
from fastapi import APIRouter, Depends, HTTPException

router = APIRouter(prefix="/secure")

# Safe configuration loading
DATABASE_PASSWORD = os.getenv("DB_PASSWORD")

# Placeholder/testing value (should not trigger hardcoded secret rule)
TEST_TOKEN = "changeme"


def get_current_user():
    return {"id": "user_123", "role": "admin", "tenant_id": "tenant_1"}


# Authenticated endpoint with ownership check
@router.get("/users/{user_id}")
async def get_user_secure(user_id: str, current_user: dict = Depends(get_current_user)):
    # Ownership comparison protects object
    if current_user["id"] != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")

    user = db.get("User", user_id)
    return user


# Tenant-isolated query
@router.get("/items/{item_id}")
async def get_item_tenant(item_id: str, current_user: dict = Depends(get_current_user)):
    # Tenant-scoped lookup
    item = session.query("Item").filter(Item.tenant_id == current_user["tenant_id"]).filter(Item.id == item_id).first()
    return item
