from fastapi import FastAPI, Body

app = FastAPI()

@app.post("/api/v1/register")
def register(data: dict = Body(...)):
    return {"registered": True}
