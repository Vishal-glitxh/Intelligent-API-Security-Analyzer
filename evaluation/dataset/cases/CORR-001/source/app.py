from fastapi import FastAPI

app = FastAPI()

@app.get("/api/v1/admin/audit")
def get_audit_logs():
    return [{"log": "entry1"}]
