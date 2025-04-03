import random
import string
import datetime
import secrets
from flask import Blueprint, request, render_template, session, redirect, url_for, current_app
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from ddmail_webapp.models import db, Account, User, Authenticated
import ddmail_validators.validators as validators

bp = Blueprint("auth", __name__, url_prefix="/")

# Generate a token that is easy to write down on paper frpm screen.
def generate_token(length):
    alphabet = string.ascii_uppercase + string.digits
    while True:
        token = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.isupper() for c in token) and sum(c.isdigit() for c in token) >= 4):
            break
    return token

# Generate a password with digit, upparcase letters and lowercase letters.
def generate_password(length):
    alphabet = string.ascii_letters + string.digits
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password) and any(c.isupper() for c in password) and sum(c.isdigit() for c in password) >= 3):
            break
    return password

# Check if a user is authenticated, if the user is authenticated the user id will be returned else None.
def is_athenticated(cookie):
    # Validate the cookie
    if validators.is_cookie_allowed(cookie) != True:
        return None

    # Try to find the cookie in the db.
    authenticated = Authenticated.query.filter_by(cookie = cookie).first()

    # Check if the cookie was in the authenticated table.
    if authenticated == None:
        return None

    # Get the cookie valid_to time in datetime object.
    valid_to = datetime.datetime.strptime(str(authenticated.valid_to), '%Y-%m-%d %H:%M:%S')

    # Get current time in datetime object.
    now_time = datetime.datetime.now()

    # Check if cookie is still valid.
    if now_time > valid_to:
        return None

    # Get the user object from db.
    user_from_db = db.session.query(User).filter(User.id == authenticated.user_id).first()

    # User is authenticated, return user object.
    return user_from_db

@bp.route("/register", methods=['POST', 'GET'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    if request.method == 'POST':
        ph = PasswordHasher()

        # Generate new account.
        account = generate_token(12)
        payment_token = generate_token(12)

        # Add new org to the db.
        new_account = Account(account=account, payment_token=payment_token, funds_in_sek=0, is_enabled=False, is_gratis=False, total_storage_space_g=0 ,created=datetime.datetime.now())
        db.session.add(new_account)
        db.session.commit()

        # Generate all the user data.
        user = generate_token(12)
        cleartext_password = generate_password(24)
        cleartext_password_key = generate_password(4096)

        # Generate password hashes for password and password-key.
        password_hash = ph.hash(cleartext_password)
        password_key_hash = ph.hash(cleartext_password_key)

        # Add the user data to the db.
        new_user = User(account_id=new_account.id, user=user, password_hash=password_hash,password_key_hash=password_key_hash)
        db.session.add(new_user)
        db.session.commit()

        # Give the data to the user.
        current_app.logger.info("created new account: " + account  + " with new user: " + user)
        return render_template('user_created.html',account=new_account.account,user=user,cleartext_password=cleartext_password,cleartext_password_key=cleartext_password_key)

@bp.route("/login", methods=['POST', 'GET'])
def login():
    current_user = None

    if request.method == 'GET':
        return render_template('login.html',current_user = current_user)
    if request.method == 'POST':
        ph = PasswordHasher()

        # Get the data from the forms.
        user_from_form = request.form["user"].strip()
        cleartext_password_from_form = request.form["password"].strip()
        file = request.files['key']
        cleartext_password_key_from_form = file.read().strip().decode("utf-8")

        # Check that form has data.
        if not user_from_form or not cleartext_password_from_form or not cleartext_password_key_from_form:
            # Login failed
            current_app.logger.warning("failed login, data is missing")
            return render_template('message.html',headline="Login error",message="Failed to login, wrong username and/or password and/or key.",current_user=current_user)

        # Validate the form data username.
        if validators.is_username_allowed(user_from_form) != True:
            # Login failed.
            current_app.logger.warning("failed login, username validation failed")
            return render_template('message.html',headline="Login error",message="Failed to login, wrong username and/or password and/or key.",current_user=current_user)

        # Validate the form data password.
        if validators.is_password_allowed(cleartext_password_from_form) != True:
            # Login failed.
            current_app.logger.warning("failed login, password validation failed")
            return render_template('message.html',headline="Login error",message="Failed to login, wrong username and/or password and/or key.",current_user=current_user)

        # Validate the form data password key.
        if validators.is_password_key_allowed(cleartext_password_key_from_form) != True:
            # Login failed.
            current_app.logger.warning("failed login, password key validation failed")
            return render_template('message.html',headline="Login error",message="Failed to login, wrong username and/or password and/or key.",current_user=current_user)

        # Get the user data from db and check that user exist.
        user_from_db = db.session.query(User).filter(User.user == user_from_form).first()
        if not user_from_db:
            # Login failed.
            current_app.logger.warning("failed login, user " + user_from_form + " do not exsist in db")
            return render_template('message.html',headline="Login error",message="Failed to login, wrong username and/or password and/or key.",current_user=current_user)

        # Check password hash.
        try:
            if ph.verify(user_from_db.password_hash, cleartext_password_from_form) != True:
                # Login failed.
                current_app.logger.warning("failed login, user " + user_from_db.user + " belonging to account " + user_from_db.account.account + " wrong password")
                return render_template('message.html',headline="Login error",message="Failed to login, wrong username and/or password and/or key.",current_user=current_user)
        except VerifyMismatchError:
            # Login failed.
            current_app.logger.warning("failed login, user " + user_from_db.user + " belonging to account " + user_from_db.account.account + " wrong password")
            return render_template('message.html',headline="Login error",message="Failed to login, wrong username and/or password and/or key.",current_user=current_user)

        # Check password key hash.
        try:
            if ph.verify(user_from_db.password_key_hash, cleartext_password_key_from_form) != True:
                # Login failed.
                current_app.logger.warning("failed login, user " + user_from_db.user + " belonging to account " + user_from_db.account.account + " wrong password key")
                return render_template('message.html',headline="Login error",message="Failed to login, wrong username and/or password and/or key.",current_user=current_user)
        except VerifyMismatchError:
            # Login failed.
            current_app.logger.warning("failed login, user " + user_from_db.user + " belonging to account " + user_from_db.account.account + " wrong password key")
            return render_template('message.html',headline="Login error",message="Failed to login, wrong username and/or password and/or key.",current_user=current_user)

        # Login succeeded
        # Generate a secret random cookie.
        cookie = generate_password(128)

        # Sign the cookie and store it in the browser.
        session["secret"] = cookie

        # Store the cookie in the db together with expire time.
        authenticated = Authenticated(cookie,user_from_db.id,datetime.datetime.now() + datetime.timedelta(hours=3))
        db.session.add(authenticated)
        db.session.commit()

        current_app.logger.info("successful login for user " + user_from_db.user + " belonging to account " + user_from_db.account.account)
        return redirect('/settings')

@bp.route("/logout")
def logout():
    # Check if user is authenticated.
    if "secret" in session:
        current_user = is_athenticated(session["secret"])
        current_app.logger.debug("secret is in session")

        if current_user != None:
            # Delete the cookie from db.
            current_app.logger.debug("deleting user with id " + str(current_user.id) + " from authenticated in db")
            db.session.query(Authenticated).filter(Authenticated.user_id == current_user.id).delete()
            db.session.commit()
    else:
        current_app.logger.debug("secret is not in session")
        current_user = None

    session.clear()
    return redirect('/')
