from flask import Blueprint, current_app, make_response

bp = Blueprint("well_known", __name__, url_prefix="/")


@bp.route("/.well-known/mta-sts.txt")
def mtasts():
    """
    Serve the MTA-STS policy file for email security.

    This function provides the Mail Transfer Agent Strict Transport Security
    policy file that defines security requirements for SMTP connections.
    Essential for email security and preventing man-in-the-middle attacks.

    The mx hosts are dynamically set from the MTA_STS_MX configuration variable,
    which is a list of hostnames. Each entry produces a separate mx: line in the
    response.

    Returns:
        Response: Flask response with dynamically generated mta-sts.txt content

    Request Form Parameters:
        None: This endpoint does not require form parameters

    Error Responses:
        None: This endpoint does not return error responses

    Success Response:
        Returns dynamically generated mta-sts.txt with MTA-STS security policy
    """
    current_app.logger.debug("/.well-known/mta-sts.txt")

    mta_sts_mx_list = current_app.config["MTA_STS_MX"]

    mx_lines = "".join(f"mx: {mx}\n" for mx in mta_sts_mx_list)
    content = f"version: STSv1\nmode: enforce\n{mx_lines}max_age: 604800\n"

    response = make_response(content)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    return response


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
