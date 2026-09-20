from fastapi import FastAPI, Body

app = FastAPI()

@app.post("/api/v1/search")
def search(payload: dict = Body(...)):
    query_str = payload.get("query")
    return {"results": [query_str]}
