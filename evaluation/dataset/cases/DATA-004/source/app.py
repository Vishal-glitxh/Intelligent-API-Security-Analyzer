from fastapi import FastAPI

app = FastAPI()

@app.get("/api/v1/items")
def get_items():
    return [{"item_name": "sauce", "secret_sauce_recipe_name": "Grandma Classic"}]
