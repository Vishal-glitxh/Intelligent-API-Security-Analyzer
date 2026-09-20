from fastapi import FastAPI, HTTPException, Depends

app = FastAPI()

def get_current_user():
    return {"user_id": "user123"}

@app.get("/api/v1/documents/{doc_id}")
def get_document(doc_id: str, user: dict = Depends(get_current_user)):
    doc = {"id": doc_id, "owner_id": "user123"}
    if doc["owner_id"] != user["user_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    return doc
