from flask import Blueprint, session, render_template, current_app
from ddmail_webapp.auth import is_athenticated

bp = Blueprint("unauthenticated", __name__, url_prefix="/")


@bp.route("/")
def main():
    """
    Render the main landing page of the application.

    This function displays the homepage of the DDMail web application, showing
    basic information about the service and navigation options for both
    authenticated and unauthenticated users.

    Returns:
        Response: Flask response with rendered main.html template

    Request Form Parameters:
        None: This endpoint does not require form parameters

    Error Responses:
        None: This endpoint does not return error responses

    Success Response:
        Renders main.html template with current user authentication status
    """
    # Check if user is athenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
    else:
        current_user = None

    return render_template("main.html", current_user=current_user)


@bp.route("/help")
def help():
    """
    Render the help page with DNS configuration information.

    This function displays comprehensive help documentation including DNS record
    configuration requirements for email setup (MX, SPF, DKIM, DMARC records).
    It loads configuration values and passes them to the template.

    Returns:
        Response: Flask response with rendered help.html template

    Request Form Parameters:
        None: This endpoint does not require form parameters

    Error Responses:
        None: This endpoint does not return error responses

    Success Response:
        Renders help.html template with DNS configuration details and user status
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

    return render_template(
        "help.html",
        current_user=current_user,
        mx_record_host=mx_record_host,
        mx_record_priority=mx_record_priority,
        spf_record=spf_record,
        dkim_cname_record1=dkim_cname_record1,
        dkim_cname_record2=dkim_cname_record2,
        dkim_cname_record3=dkim_cname_record3,
        dmarc_record=dmarc_record,
    )


@bp.route("/about")
def about():
    """
    Render the about page of the application.

    This function displays information about the DDMail service, including
    company background, mission statement, and service overview for
    potential and current users.

    Returns:
        Response: Flask response with rendered about.html template

    Request Form Parameters:
        None: This endpoint does not require form parameters

    Error Responses:
        None: This endpoint does not return error responses

    Success Response:
        Renders about.html template with company information and user status
    """
    # Check if user is athenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
    else:
        current_user = None

    return render_template("about.html", current_user=current_user)


@bp.route("/pricing_and_payment")
def pricing_and_payment():
    """
    Render the pricing and payment information page.

    This function displays available subscription plans, pricing tiers,
    and payment options. It shows cost structure and billing information
    for potential customers to make informed decisions.

    Returns:
        Response: Flask response with rendered pricing_and_payment.html template

    Request Form Parameters:
        None: This endpoint does not require form parameters

    Error Responses:
        None: This endpoint does not return error responses

    Success Response:
        Renders pricing_and_payment.html template with pricing information and user status
    """
    # Check if user is athenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
    else:
        current_user = None

    return render_template("pricing_and_payment.html", current_user=current_user)


@bp.route("/terms")
def terms():
    """
    Render the terms of service page.

    This function displays the legal terms and conditions for using the
    DDMail service. It provides users with important legal information
    regarding service usage, privacy, and user obligations.

    Returns:
        Response: Flask response with rendered terms.html template

    Request Form Parameters:
        None: This endpoint does not require form parameters

    Error Responses:
        None: This endpoint does not return error responses

    Success Response:
        Renders terms.html template with terms of service and user status
    """
    # Check if user is athenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
    else:
        current_user = None

    return render_template("terms.html", current_user=current_user)


@bp.route("/contact")
def contact():
    """
    Render the contact page.

    This function displays contact information and support options for users
    to get assistance. It provides various ways to reach customer support
    and technical help resources.

    Returns:
        Response: Flask response with rendered contact.html template

    Request Form Parameters:
        None: This endpoint does not require form parameters

    Error Responses:
        None: This endpoint does not return error responses

    Success Response:
        Renders contact.html template with contact information and user status
    """
    # Check if user is athenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
    else:
        current_user = None

    return render_template("contact.html", current_user=current_user)


@bp.route("/robots.txt")
def robots():
    """
    Serve the robots.txt file for search engine crawlers.

    This function provides search engines with instructions about which
    parts of the site should or should not be crawled and indexed.
    Essential for SEO and controlling bot access.

    Returns:
        Response: Flask response with static robots.txt file

    Request Form Parameters:
        None: This endpoint does not require form parameters

    Error Responses:
        None: This endpoint does not return error responses

    Success Response:
        Returns static robots.txt file with web crawler instructions
    """
    return current_app.send_static_file("robots.txt")


@bp.route("/sitemap.xml")
def sitemap():
    """
    Serve the sitemap.xml file for search engine crawlers.

    This function provides search engines with a structured list of all
    pages on the site that should be indexed, along with metadata about
    each page including last modification dates and priorities.

    Returns:
        Response: Flask response with static sitemap.xml file

    Request Form Parameters:
        None: This endpoint does not require form parameters

    Error Responses:
        None: This endpoint does not return error responses

    Success Response:
        Returns static sitemap.xml file with site structure information
    """
    return current_app.send_static_file("sitemap.xml")
