# Flask sample fixture for static security analysis
from flask import Blueprint, abort

users_bp = Blueprint("users_bp", __name__, url_prefix="/api/users")


def login_required(f):
    return f


@users_bp.route("/<user_id>", methods=["GET"])
@login_required
def get_user_profile(user_id):
    # Role check authorization
    if current_user.role != "admin":
        abort(403)
    user = repo.get_by_id(user_id)
    return user


@users_bp.route("/<int:item_id>/delete", methods=["DELETE"])
def delete_item_unprotected(item_id):
    # No auth, object lookup without check
    item = repo.find_by_id(item_id)
    return {"deleted": True}
