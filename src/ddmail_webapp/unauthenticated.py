from flask import Blueprint, session, render_template, current_app
from ddmail_webapp.auth import is_athenticated

bp = Blueprint("unauthenticated", __name__, url_prefix="/")

@bp.route("/")
def main():
    # Check if user is athenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
    else:
        current_user = None

    return render_template('main.html', current_user = current_user)

@bp.route("/help")
def help():
    # Check if user is athenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
    else:
        current_user = None

    mx_record_host = current_app.config["MX_RECORD_HOST"]
    mx_record_priority = current_app.config["MX_RECORD_PRIORITY"]
    spf_record = current_app.config["SPF_RECORD"]
    dkim_record = current_app.config["DKIM_RECORD"]
    dmarc_record = current_app.config["DMARC_RECORD"]

    return render_template('help.html',current_user=current_user,mx_record_host=mx_record_host,mx_record_priority=mx_record_priority,spf_record=spf_record,dkim_record=dkim_record,dmarc_record=dmarc_record)

@bp.route("/about")
def about():
    # Check if user is athenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
    else:
        current_user = None

    return render_template('about.html',current_user=current_user)

@bp.route("/pricing_and_payment")
def pricing_and_payment():
    # Check if user is athenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
    else:
        current_user = None

    return render_template('pricing_and_payment.html',current_user=current_user)

@bp.route("/terms")
def terms():
    # Check if user is athenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
    else:
        current_user = None

    return render_template('terms.html',current_user=current_user)

@bp.route("/contact")
def contact():
    # Check if user is athenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
    else:
        current_user = None

    return render_template('contact.html',current_user=current_user)

@bp.route("/robots.txt")
def robots():
    return current_app.send_static_file('robots.txt')

@bp.route("/sitemap.xml")
def sitemap():
    return current_app.send_static_file('sitemap.xml')
