from fastapi import FastAPI, Depends, Header, HTTPException

app = FastAPI()

def verify_token(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return authorization

@app.get("/api/v1/profile")
def get_profile(token: str = Depends(verify_token)):
    return {"user": "alice"}
