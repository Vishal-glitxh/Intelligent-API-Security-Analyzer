from fastapi import FastAPI, Header

app = FastAPI()

@app.get("/api/v1/reports/{report_id}")
def get_report(report_id: str, authorization: str = Header(...)):
    return {"report_id": report_id, "status": "FINAL"}
