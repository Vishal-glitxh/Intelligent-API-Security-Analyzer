from fastapi import FastAPI
from pydantic import BaseModel, Field, EmailStr

app = FastAPI()

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=20)
    email: EmailStr

@app.post("/api/v1/users")
def create_user(user: UserCreate):
    return {"status": "created"}
