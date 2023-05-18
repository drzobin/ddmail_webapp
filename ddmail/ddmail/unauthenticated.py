from flask import Blueprint, session, render_template
from ddmail.auth import is_athenticated

bp = Blueprint("unauthenticated", __name__, url_prefix="/")

@bp.route("/")
def main():
    # Check if user is athenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
    else:
        current_user = None

    return render_template('main.html', current_user = current_user)

@bp.route("/about")
def about():
    # Check if user is athenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
    else:
        current_user = None

    return render_template('about.html',current_user=current_user)

