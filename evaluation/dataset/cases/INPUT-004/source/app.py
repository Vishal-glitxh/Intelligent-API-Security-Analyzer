from fastapi import FastAPI, Depends, Body, HTTPException

app = FastAPI()

def validate_comment_body(body: dict = Body(...)):
    text = body.get("text", "")
    if len(text) > 500:
        raise HTTPException(status_code=400, detail="Too long")
    return body

@app.post("/api/v1/comments")
def add_comment(valid_body: dict = Depends(validate_comment_body)):
    return {"status": "posted"}
