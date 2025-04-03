from flask import Blueprint, current_app

bp = Blueprint("well_known", __name__, url_prefix="/")

@bp.route("/.well-known/mta-sts.txt")
def mtasts():
    current_app.logger.debug("/.well-known/mta-sts.txt")
    return current_app.send_static_file('mta-sts.txt')

@bp.route("/security.txt")
@bp.route("/.well-known/security.txt")
def security():
    current_app.logger.debug("/.well-known/security.txt")
    return current_app.send_static_file('security.txt')
