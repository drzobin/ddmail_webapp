from flask import Blueprint, current_app

bp = Blueprint("well_known", __name__, url_prefix="/")


@bp.route("/.well-known/mta-sts.txt")
def mtasts():
    """
    Serve the MTA-STS policy file for email security.

    This function provides the Mail Transfer Agent Strict Transport Security
    policy file that defines security requirements for SMTP connections.
    Essential for email security and preventing man-in-the-middle attacks.

    Returns:
        Response: Flask response with static mta-sts.txt file

    Request Form Parameters:
        None: This endpoint does not require form parameters

    Error Responses:
        None: This endpoint does not return error responses

    Success Response:
        Returns static mta-sts.txt file with MTA-STS security policy
    """
    current_app.logger.debug("/.well-known/mta-sts.txt")
    return current_app.send_static_file("mta-sts.txt")


@bp.route("/security.txt")
@bp.route("/.well-known/security.txt")
def security():
    """
    Serve the security.txt file for vulnerability disclosure.

    This function provides security contact information and vulnerability
    disclosure procedures for security researchers. Available at both
    root level and RFC 9116 compliant well-known location.

    Returns:
        Response: Flask response with static security.txt file

    Request Form Parameters:
        None: This endpoint does not require form parameters

    Error Responses:
        None: This endpoint does not return error responses

    Success Response:
        Returns static security.txt file with security contact information
    """
    current_app.logger.debug("/.well-known/security.txt")
    return current_app.send_static_file("security.txt")

