from flask import Blueprint, session, render_template, current_app
from ddmail_webapp.auth import is_athenticated

bp = Blueprint("unauthenticated", __name__, url_prefix="/")

@bp.route("/")
def main():
    """Render the main landing page of the application.

    Checks if the user is authenticated and passes the user object to the template
    if they are. Otherwise, passes None as the current user.

    Returns:
        HTML rendered main page template
    """
    # Check if user is athenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
    else:
        current_user = None

    return render_template('main.html', current_user = current_user)

@bp.route("/help")
def help():
    """Render the help page with DNS configuration information.

    Provides information about MX, SPF, DKIM, and DMARC records needed for
    email setup. Checks user authentication status to customize the page display.

    Returns:
        HTML rendered help page template with DNS configuration details
    """
    # Check if user is athenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
    else:
        current_user = None

    mx_record_host = current_app.config["MX_RECORD_HOST"]
    mx_record_priority = current_app.config["MX_RECORD_PRIORITY"]
    spf_record = current_app.config["SPF_RECORD"]
    dkim_cname_record1 = current_app.config["DKIM_CNAME_RECORD1"]
    dkim_cname_record2 = current_app.config["DKIM_CNAME_RECORD2"]
    dkim_cname_record3 = current_app.config["DKIM_CNAME_RECORD3"]
    dmarc_record = current_app.config["DMARC_RECORD"]

    return render_template('help.html',current_user=current_user,mx_record_host=mx_record_host,mx_record_priority=mx_record_priority,spf_record=spf_record,dkim_cname_record1=dkim_cname_record1,dkim_cname_record2=dkim_cname_record2,dkim_cname_record3=dkim_cname_record3,dmarc_record=dmarc_record)

@bp.route("/about")
def about():
    """Render the about page of the application.

    Displays information about the service, company, or team behind DDMail.
    Checks user authentication status to customize the page display.

    Returns:
        HTML rendered about page template
    """
    # Check if user is athenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
    else:
        current_user = None

    return render_template('about.html',current_user=current_user)

@bp.route("/pricing_and_payment")
def pricing_and_payment():
    """Render the pricing and payment information page.

    Displays subscription plans, pricing tiers, and payment options
    available to users. Checks authentication status to customize the page.

    Returns:
        HTML rendered pricing and payment page template
    """
    # Check if user is athenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
    else:
        current_user = None

    return render_template('pricing_and_payment.html',current_user=current_user)

@bp.route("/terms")
def terms():
    """Render the terms of service page.

    Displays the legal terms and conditions for using the DDMail service.
    Checks user authentication status to customize the page display.

    Returns:
        HTML rendered terms page template
    """
    # Check if user is athenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
    else:
        current_user = None

    return render_template('terms.html',current_user=current_user)

@bp.route("/contact")
def contact():
    """Render the contact page.

    Displays contact information and possibly a contact form for users
    to get in touch with support. Checks authentication status to customize the page.

    Returns:
        HTML rendered contact page template
    """
    # Check if user is athenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
    else:
        current_user = None

    return render_template('contact.html',current_user=current_user)

@bp.route("/robots.txt")
def robots():
    """Serve the robots.txt file for search engine crawlers.

    Provides search engines with instructions about which parts of the site
    should or should not be crawled and indexed.

    Returns:
        The static robots.txt file
    """
    return current_app.send_static_file('robots.txt')

@bp.route("/sitemap.xml")
def sitemap():
    """Serve the sitemap.xml file for search engine crawlers.

    Provides search engines with a structured list of all pages on the site
    that should be indexed, along with metadata about each page.

    Returns:
        The static sitemap.xml file
    """
    return current_app.send_static_file('sitemap.xml')
