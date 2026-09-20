from fastapi import FastAPI, Depends, HTTPException

app = FastAPI()

def verify_project_permission(project_id: str):
    if project_id == "forbidden":
        raise HTTPException(status_code=403)
    return True

@app.get("/api/v1/projects/{project_id}")
def get_project(project_id: str, authorized: bool = Depends(verify_project_permission)):
    return {"project_id": project_id, "name": "Project Alpha"}
