from flask import Flask

app = Flask(__name__)

@app.route("/api/v1/health", methods=["GET"])
def health():
    pass

@app.route("/users/<user_id>", methods=["GET"])
def get_user(user_id):
    pass

@app.route("/items/list", methods=["GET"])
def list_items():
    pass

@app.route("/v1/ambiguous/<item_id>", methods=["GET"])
def get_ambiguous_a(item_id):
    pass

@app.route("/v1/ambiguous/<res_id>", methods=["GET"])
def get_ambiguous_b(res_id):
    pass

