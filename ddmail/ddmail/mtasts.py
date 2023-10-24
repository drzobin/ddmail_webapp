from flask import Blueprint, current_app

bp = Blueprint("mtasts", __name__, url_prefix="/")

@bp.route("/.well-known/mta-sts.txt")
def mtasts():
    return current_app.send_static_file('mta-sts.txt')
