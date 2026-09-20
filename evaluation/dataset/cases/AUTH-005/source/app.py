from fastapi import FastAPI, APIRouter, Depends, Header, HTTPException

app = FastAPI()

def verify_session(x_session: str = Header(...)):
    if not x_session:
        raise HTTPException(status_code=401)
    return x_session

router = APIRouter(dependencies=[Depends(verify_session)])

@router.get("/api/v1/secure/data")
def get_secure_data():
    return {"data": "secret"}

app.include_router(router)
