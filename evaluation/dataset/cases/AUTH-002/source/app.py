from fastapi import FastAPI

app = FastAPI()

@app.get("/api/v1/admin/users")
def get_admin_users():
    return [{"id": 1, "username": "admin"}]
