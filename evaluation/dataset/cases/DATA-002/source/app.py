from fastapi import FastAPI

app = FastAPI()

@app.get("/api/v1/users/{id}")
def get_user_details(id: str):
    return {
        "username": "bob",
        "password_hash": "$2b$12$eImiTXuWVxfM37uY4JANjO5E.8B1/...",
        "ssn": "000-12-3456"
    }
