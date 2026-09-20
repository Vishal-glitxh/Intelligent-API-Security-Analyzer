from fastapi import FastAPI

app = FastAPI()

@app.get("/api/v1/products")
def list_products():
    return [{"id": 1, "name": "Widget", "price": 9.99}]
