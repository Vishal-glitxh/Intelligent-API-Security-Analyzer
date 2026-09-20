from fastapi import FastAPI, Depends, Header

app = FastAPI()

def get_current_user(authorization: str = Header(...)):
    return {"user_id": "u1"}

@app.get("/api/v1/orders/{order_id}")
def get_order(order_id: str, user: dict = Depends(get_current_user)):
    return {"order_id": order_id, "total": 99.99}
