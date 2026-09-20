from fastapi import FastAPI

app = FastAPI()

@app.get("/api/v1/accounts/{account_id}")
def get_account(account_id: str):
    return {"account_id": account_id, "balance": 10000}
