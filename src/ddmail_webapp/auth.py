import datetime
import io
import random
import secrets
import string
from io import BytesIO
from xxlimited import new

import ddmail_validators.validators as validators
import requests
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import (
    Blueprint,
    current_app,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from ddmail_webapp.models import Account, Authenticated, Openpgp_public_key, User, db

bp = Blueprint("auth", __name__, url_prefix="/")


def generate_token(length):
    """
    Generate a secure token for user accounts and authentication.

    This function creates a cryptographically secure token using uppercase
    letters(not I, 1, 0, or O) and digits that is easy to write down and
    transcribe. The tokenensures minimum security requirements with at
    least 4 digits.

    Returns:
        str: A secure token containing uppercase letters and digits

    Parameters:
        length (int): The desired length of the generated token

    Security Requirements:
        Must contain at least one uppercase letter
        Must contain at least 4 digits
        Uses cryptographically secure random generation
        Character set: A-Z, 0-9
    """
    # Define characters to exclude.
    excluded_chars = set("1IO0")

    # Create the alphabet without excluded characters.
    alphabet = "".join(
        c for c in string.ascii_uppercase + string.digits if c not in excluded_chars
    )

    while True:
        token = "".join(secrets.choice(alphabet) for i in range(length))
        if any(c.isupper() for c in token) and sum(c.isdigit() for c in token) >= 4:
            break

    return token


def generate_password(length):
    """
    Generate a secure password with mixed character types.

    This function creates a cryptographically secure password containing
    uppercase letters, lowercase letters, and digits.

    Returns:
        str: A secure password with mixed character types

    Parameters:
        length (int): The desired length of the generated password

    Security Requirements:
        Must contain at least one lowercase letter
        Must contain at least one uppercase letter
        Must contain at least 3 digits
        Uses cryptographically secure random generation
        Character set: a-z, A-Z, 0-9
    """
    alphabet = string.ascii_letters + string.digits
    while True:
        password = "".join(secrets.choice(alphabet) for i in range(length))
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and sum(c.isdigit() for c in password) >= 3
        ):
            break
    return password


def is_athenticated(cookie):
    """
    Validate user authentication status using session cookie.

    This function checks if a provided cookie corresponds to a valid,
    non-expired user session. It validates the cookie format, checks
    database records, and verifies expiration time.

    Returns:
        User|None: User object if authenticated, None if invalid/expired

    Parameters:
        cookie (str): The session cookie to validate

    Error Responses:
        Returns None if cookie is None
        Returns None if cookie format is invalid
        Returns None if cookie not found in database
        Returns None if session has expired
        Returns None if associated user not found

     Success Response:
         User object from database if authenticated
    """
    # Check if cookie is None first
    if cookie is None:
        return None

    # Validate the cookie
    if validators.is_cookie_allowed(cookie) != True:
        return None

    # Try to find the cookie in the db.
    authenticated = Authenticated.query.filter_by(cookie=cookie).first()

    # Check if the cookie was in the authenticated table.
    if authenticated == None:
        return None

    # Get the cookie valid_to time in datetime object.
    valid_to = datetime.datetime.strptime(
        str(authenticated.valid_to), "%Y-%m-%d %H:%M:%S"
    )

    # Get current time in datetime object.
    now_time = datetime.datetime.now()

    # Check if cookie is still valid.
    if now_time > valid_to:
        return None

    # Get the user object from db.
    user_from_db = (
        db.session.query(User).filter(User.id == authenticated.user_id).first()
    )

    # User is authenticated, return user object.
    return user_from_db


@bp.route("/register", methods=["POST", "GET"])
def register():
    """
    Handle registration process.

    This function manages both GET and POST requests for user registration.
    GET requests display the registration form. POST requests takes a OpenPGP public key.
    It creates a new account with a new user, encrypting the credentials with the uploaded public
    key and then sends it to the user in a encrypted file ddmail-credentials.asc.

    Returns:
        Response: Flask response with registration form or user credentials

    Request Form Parameters:
        csrf_token (str): CSRF protection token for POST requests

    Error Responses:
        None: This endpoint does not return error responses

    Success Response:
        GET: Renders registration.html template with registration form
        POST: Returns the encrypted file ddmail-credentials.asc with the newly created credentials
    """
    if request.method == "GET":
        return render_template("register.html")
    if request.method == "POST":
        # Guard against missing form field.
        file = request.files.get("openpgp_public_key")
        if file is None or file.filename == "":
            current_app.logger.warning("openpgp public key upload missing file")
            return render_template(
                "message.html",
                headline="Register Error",
                message="Failed to upload openpgp public key because no file was provided.",
                current_user=None,
            )

        # Guard against non-UTF-8 payloads.
        try:
            openpgp_public_key = file.read().strip().decode("utf-8")
        except UnicodeDecodeError:
            current_app.logger.warning(" openpgp public key upload is not valid utf-8")
            return render_template(
                "message.html",
                headline="Register Error",
                message="Failed to upload openpgp public key because the file is not valid UTF-8 text.",
                current_user=None,
            )

        # Check if public key file is empty.
        if not openpgp_public_key:
            current_app.logger.warning("openpgp public key is empty")
            return render_template(
                "message.html",
                headline="Register Error",
                message="Failed to upload openpgp public key because uploaded public key is empty",
                current_user=None,
            )

        # Validate openpgp public key data.
        if validators.is_openpgp_public_key_allowed(openpgp_public_key) != True:
            current_app.logger.warning("validation failed")
            return render_template(
                "message.html",
                headline="Register Error",
                message="Failed to upload openpgp public key beacuse validation failed",
                current_user=None,
            )

        # Get fingerprint by send openpgp public key to ddmail openpgp keyhandler service.
        openpgp_keyhandler_url = (
            current_app.config["OPENPGP_KEYHANDLER_URL"] + "/get_fingerprint"
        )
        openpgp_keyhandler_password = current_app.config["OPENPGP_KEYHANDLER_PASSWORD"]
        try:
            r_respone = requests.post(
                openpgp_keyhandler_url,
                {
                    "public_key": openpgp_public_key,
                    "password": openpgp_keyhandler_password,
                },
                timeout=5,
            )
        except requests.exceptions.ConnectionError:
            current_app.logger.error("faild to upload openpgp public key beacuse openpgp keyhandler service do not answer")
            return render_template(
                "message.html",
                headline="Register Error",
                message="Failed to upload openpgp public key beacuse openpgp keyhandler service do not answer.",
                current_user=None,
            )

        # Check if upload was successfull.
        if r_respone.status_code != 200 or "done fingerprint: " not in str(
            r_respone.content
        ):
            current_app.logger.error("faild to upload openpgp public key beacuse openpgp keyhandler service returned error")
            return render_template(
                "message.html",
                headline="Register error",
                message="Failed to upload openpgp public key.",
                current_user=None,
            )

        # Get fingerprint of uploaded openpgp public key.
        fingerprint = str(r_respone.content, encoding="utf-8").replace(
            "done fingerprint: ", ""
        )
        fingerprint = fingerprint.strip()

        # Validate fingerprint.
        if validators.is_openpgp_key_fingerprint_allowed(fingerprint) != True:
            current_app.logger.error(
                " faild to upload openpgp public key beacuse openpgp keyhandler service returned fingerprint "
                + fingerprint
                + " that failed validation"
            )
            return render_template(
                "message.html",
                headline="Register error",
                message="Openpgp public key fingerprint validation failed.",
                current_user=None,
            )

        # Check that openpgp public key fingerprint do not exist in db
        is_fingerprint_uniq = (
            db.session.query(Openpgp_public_key)
            .filter(
                Openpgp_public_key.fingerprint == fingerprint,
            )
            .count()
        )
        if is_fingerprint_uniq != 0:
            current_app.logger.error(
                " faild to upload openpgp public key beacuse openpgp keyhandler service returned fingerprint "
                + fingerprint
                + " that already exist in db"
            )
            return render_template(
                "message.html",
                headline="Register error",
                message="Openpgp public key fingerprint already exist in database",
                current_user=None,
            )

        # Generate new account.
        account = generate_token(12)
        payment_token = generate_token(24)

        # Add new account to the db.
        new_account = Account(
            account=account,
            payment_token=payment_token,
            funds_in_sek=0,
            is_enabled=False,
            is_gratis=False,
            total_storage_space_g=1,
            created=datetime.datetime.now(),
        )
        db.session.add(new_account)
        db.session.commit()

        # Insert openpgp public key and fingerprint to db.
        new_openpgp_public_key = Openpgp_public_key(
            account_id=new_account.id,
            fingerprint=fingerprint,
            public_key=openpgp_public_key,
        )
        db.session.add(new_openpgp_public_key)
        db.session.commit()

        current_app.logger.debug(
            "account "
            + new_account.account
            + " uploaded openpgp public key with fingerprint"
            + fingerprint
        )

        ph = PasswordHasher()

        # Generate all the user data.
        user = generate_token(12)
        cleartext_password = generate_password(24)
        cleartext_password_key = generate_password(128)

        # Generate password hashes for password and password-key.
        password_hash = ph.hash(cleartext_password)
        password_key_hash = ph.hash(cleartext_password_key)

        # Add the user data to the db.
        new_user = User(
            account_id=new_account.id,
            openpgp_public_key_id=new_openpgp_public_key.id,
            user=user,
            password_hash=password_hash,
            password_key_hash=password_key_hash,
        )
        db.session.add(new_user)
        db.session.commit()

        cleartext_data = (
            "Account:"
            + account
            + "\nUsername:"
            + user
            + "\nOpenPGP public key fingerprint:"
            + fingerprint
            + "\nPassword:"
            + cleartext_password
            + "\nKey file data:"
            + cleartext_password_key
            + "\n"
        )

        openpgp_keyhandler_url = (
            current_app.config["OPENPGP_KEYHANDLER_URL"] + "/encrypt_data"
        )

        try:
            r_respone = requests.post(
                openpgp_keyhandler_url,
                {
                    "public_key": openpgp_public_key,
                    "password": openpgp_keyhandler_password,
                    "cleartext_data": str(cleartext_data)
                },
                timeout=5,
            )
        except requests.exceptions.ConnectionError:
            current_app.logger.error(
                "user "
                + new_user.user
                + " account "
                + new_account.account
                + " faild to encrypt cleartext data beacuse openpgp keyhandler service do not answer"
            )
            return render_template(
                "message.html",
                headline="Register Error",
                message="Failed to encrypt cleartext data beacuse openpgp keyhandler service do not answer.",
                current_user=None,
            )

        # Check if encryption was successfull.
        if r_respone.status_code != 200 or "done encrypted_data:" not in str(
            r_respone.content
        ):
            current_app.logger.error(
                "user "
                + new_user.user
                + " account "
                + new_account.account
                + " faild to encrypt cleartext data beacuse openpgp keyhandler service returned error"
            )
            return render_template(
                "message.html",
                headline="Register error",
                message="Failed to encrypt cleartext data beacuse openpgp keyhandler service returned error",
                current_user=None,
            )

        # Get encrypted data.
        encrypted_data = str(r_respone.content, encoding="utf-8").replace(
            "done encrypted_data:", ""
        )
        encrypted_data = encrypted_data.strip()

        current_app.logger.info(
            "created new account: " + account + " with new user: " + user + " with openpgp public key fingerprint: " + fingerprint
        )

        file_stream = io.BytesIO(encrypted_data.encode('utf-8'))

        # Send the encrypted credentials as an attachment to the user.
        return send_file(
            file_stream,
            mimetype='text/plain',
            as_attachment=True,
            download_name='ddmail-credentials.asc'
        )


@bp.route("/login", methods=["POST", "GET"])
def login():
    """
    Handle user authentication and session establishment.

    This function manages user login process with multi-factor authentication
    using username, password, and key file. It validates credentials,
    creates secure sessions, and redirects authenticated users.

    Returns:
        Response: Flask response with login form, error message, or redirect

    Request Form Parameters:
        user (str): Username for authentication
        password (str): User's password
        key (file): Encryption key file upload

    Error Responses:
        "Failed to login, wrong username and/or password and/or key": If form data is missing or empty
        "Failed to login, wrong username and/or password and/or key": If username validation fails
        "Failed to login, wrong username and/or password and/or key": If password validation fails
        "Failed to login, wrong username and/or password and/or key": If key validation fails
        "Failed to login, wrong username and/or password and/or key": If user not found in database
        "Failed to login, wrong username and/or password and/or key": If password verification fails
        "Failed to login, wrong username and/or password and/or key": If key verification fails

    Success Response:
        GET: Renders login.html template with authentication form
        POST: Redirect to /settings page with established session
    """
    current_user = None

    if request.method == "GET":
        return render_template("login.html", current_user=current_user)
    if request.method == "POST":
        ph = PasswordHasher()

        # Get the data from the forms.
        user_from_form = request.form["user"].strip()
        cleartext_password_from_form = request.form["password"].strip()
        file = request.files["key"]
        cleartext_password_key_from_form = file.read().strip().decode("utf-8")

        # Check that form has data.
        if (
            not user_from_form
            or not cleartext_password_from_form
            or not cleartext_password_key_from_form
        ):
            # Login failed
            current_app.logger.warning("failed login, data is missing")
            return render_template(
                "message.html",
                headline="Login error",
                message="Failed to login, wrong username and/or password and/or key.",
                current_user=current_user,
            )

        # Validate the form data username.
        if validators.is_username_allowed(user_from_form) != True:
            # Login failed.
            current_app.logger.warning("failed login, username validation failed")
            return render_template(
                "message.html",
                headline="Login error",
                message="Failed to login, wrong username and/or password and/or key.",
                current_user=current_user,
            )

        # Validate the form data password.
        if validators.is_password_allowed(cleartext_password_from_form) != True:
            # Login failed.
            current_app.logger.warning("failed login, password validation failed")
            return render_template(
                "message.html",
                headline="Login error",
                message="Failed to login, wrong username and/or password and/or key.",
                current_user=current_user,
            )

        # Default to 128-bit password key length, but allow 4096-bit.
        password_key_len = 128
        if len(cleartext_password_key_from_form) == 4096:
            password_key_len = 4096

        # Validate the form data password key.
        if validators.is_password_key_allowed(cleartext_password_key_from_form, key_len=password_key_len) != True:
            # Login failed.
            current_app.logger.warning("failed login, password key validation failed")
            return render_template(
                "message.html",
                headline="Login error",
                message="Failed to login, wrong username and/or password and/or key.",
                current_user=current_user,
            )

        # Get the user data from db and check that user exist.
        user_from_db = (
            db.session.query(User).filter(User.user == user_from_form).first()
        )
        if not user_from_db:
            # Login failed.
            current_app.logger.warning(
                "failed login, user " + user_from_form + " do not exsist in db"
            )
            return render_template(
                "message.html",
                headline="Login error",
                message="Failed to login, wrong username and/or password and/or key.",
                current_user=current_user,
            )

        # Check password hash.
        try:
            if (
                ph.verify(user_from_db.password_hash, cleartext_password_from_form)
                != True
            ):
                # Login failed.
                current_app.logger.warning(
                    "failed login, user "
                    + user_from_db.user
                    + " belonging to account "
                    + user_from_db.account.account
                    + " wrong password"
                )
                return render_template(
                    "message.html",
                    headline="Login error",
                    message="Failed to login, wrong username and/or password and/or key.",
                    current_user=current_user,
                )
        except VerifyMismatchError:
            # Login failed.
            current_app.logger.warning(
                "failed login, user "
                + user_from_db.user
                + " belonging to account "
                + user_from_db.account.account
                + " wrong password"
            )
            return render_template(
                "message.html",
                headline="Login error",
                message="Failed to login, wrong username and/or password and/or key.",
                current_user=current_user,
            )

        # Check password key hash.
        try:
            if (
                ph.verify(
                    user_from_db.password_key_hash,
                    cleartext_password_key_from_form,
                )
                != True
            ):
                # Login failed.
                current_app.logger.warning(
                    "failed login, user "
                    + user_from_db.user
                    + " belonging to account "
                    + user_from_db.account.account
                    + " wrong password key"
                )
                return render_template(
                    "message.html",
                    headline="Login error",
                    message="Failed to login, wrong username and/or password and/or key.",
                    current_user=current_user,
                )
        except VerifyMismatchError:
            # Login failed.
            current_app.logger.warning(
                "failed login, user "
                + user_from_db.user
                + " belonging to account "
                + user_from_db.account.account
                + " wrong password key"
            )
            return render_template(
                "message.html",
                headline="Login error",
                message="Failed to login, wrong username and/or password and/or key.",
                current_user=current_user,
            )

        # Login succeeded
        # Generate a secret random cookie.
        cookie = generate_password(128)

        # Sign the cookie and store it in the browser.
        session["secret"] = cookie

        # Store the cookie in the db together with expire time.
        authenticated = Authenticated(
            cookie,
            user_from_db.id,
            datetime.datetime.now() + datetime.timedelta(minutes=30),
        )
        db.session.add(authenticated)
        db.session.commit()

        current_app.logger.info(
            "successful login for user "
            + user_from_db.user
            + " belonging to account "
            + user_from_db.account.account
        )
        return redirect("/settings")


@bp.route("/logout", methods=["POST"])
def logout():
    """
    Handle user logout and session cleanup.

    This function terminates user sessions by clearing browser cookies
    and removing authentication records from the database.

    Returns:
        Response: Flask redirect to home page (/)

    Request Form Parameters:
        None: This endpoint does not require form parameters

    Error Responses:
        None: This endpoint does not return error responses

    Success Response:
        Redirect to home page (/) with cleared session data
    """
    # Check if user is authenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
        current_app.logger.debug("secret is in session")

        if current_user != None:
            # Delete the cookie from db.
            current_app.logger.debug(
                "deleting user with id "
                + str(current_user.id)
                + " from authenticated in db"
            )
            db.session.query(Authenticated).filter(
                Authenticated.user_id == current_user.id
            ).delete()
            db.session.commit()
    else:
        current_app.logger.debug("secret is not in session")
        current_user = None

    session.clear()
    return redirect("/")
