import pytest
import re
from io import BytesIO
from flask import session
from werkzeug.http import parse_cookie
from tests.helpers import get_csrf_token
from tests.helpers import get_register_data
from ddmail_webapp.auth import (
    is_athenticated,
    generate_password,
    generate_token,
)
from ddmail_webapp.models import (
    db,
    Account,
    Email,
    Account_domain,
    Alias,
    Global_domain,
    User,
    Authenticated,
)
import ddmail_validators.validators as validators


def test_generate_password():
    """Test password generation requirements

    This test verifies that the generate_password function produces passwords
    that meet all security requirements including proper length, character
    composition with uppercase, lowercase, and digit requirements.
    """
    # Test to see that length is 24.
    password = generate_password(24)
    assert len(password) == 24

    # Test to see that all chars in string is uppercase A-Z or digits 0-9 or lowercase a-z.
    assert validators.is_password_allowed(password) == True

    # Test that token contain both uppercase, lowercase and digits.
    contains_uppercase = any(char.isupper() for char in password)
    contains_lowercase = any(char.islower() for char in password)
    contains_digit = any(char.isdigit() for char in password)
    assert contains_uppercase == True
    assert contains_lowercase == True
    assert contains_digit == True


def test_generate_token():
    """Test token generation requirements

    This test verifies that the generate_token function produces tokens
    that meet the specified format requirements including proper length,
    uppercase letters, and minimum digit count for security.
    """
    token = generate_token(12)

    # Test to see that all chars is uppercase or digits.
    is_uppercase = token.isupper() or token.isdigit()
    assert is_uppercase == True

    # Test that token contain both uppercase and digits.
    contains_uppercase = any(char.isupper() for char in token)
    contains_digit = any(char.isdigit() for char in token)
    assert contains_uppercase == True
    assert contains_digit == True

    # Test to see that lenth is 12.
    assert len(token) == 12


def test_register_get(client):
    """Test registration page GET request

    This test verifies that the registration page loads correctly with
    all expected navigation elements and registration instructions
    displayed to unauthenticated users.
    """
    response = client.get("/register")
    assert client.get("/register").status_code == 200
    assert b"Logged in on account: Not logged in" in response.data
    assert b"Logged in as user: Not logged in" in response.data
    assert b"Main" in response.data
    assert b"Login" in response.data
    assert b"Register" in response.data
    assert b"About" in response.data
    assert b"To create a account push the button below." in response.data


def test_login_get(client):
    """Test login page GET request

    This test verifies that the login page loads correctly with all
    required form fields (username, password, key file) and navigation
    elements displayed properly for unauthenticated users.
    """
    response = client.get("/login")
    assert client.get("/login").status_code == 200
    assert b"Logged in on account: Not logged in" in response.data
    assert b"Logged in as user: Not logged in" in response.data
    assert b"Main" in response.data
    assert b"Login" in response.data
    assert b"Register" in response.data
    assert b"About" in response.data
    assert b"Username" in response.data
    assert b"Password" in response.data
    assert b"Key file" in response.data


def test_login_post_CSRF(client):
    """Test login CSRF protection

    This test verifies that the login endpoint properly enforces CSRF
    protection by rejecting POST requests that do not include a valid
    CSRF token, returning a 400 status code.
    """
    # Test that we get 400 if the csrf_token is not set.
    assert (
        client.post(
            "/login",
            buffered=True,
            content_type="multipart/form-data",
            data={
                "user": "test",
                "password": "test",
                "key": (BytesIO(b"FILE CONTENT"), "data.key"),
            },
        ).status_code
        == 400
    )

    # Test that we get the string "The CSRF token i missing" if the csrf_token is not set.
    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": "test",
            "password": "test",
            "key": (BytesIO(b"FILE CONTENT"), "data.key"),
        },
    )
    assert b"The CSRF token is missing" in response.data


def test_login_post(client, app):
    """Test successful user login process

    This test verifies that the complete login process works correctly
    for registered users with valid credentials, including proper session
    creation and redirection to the settings page upon successful authentication.
    """
    # Get the csrf token for /register
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    # Register account and user
    response_register_post = client.post(
        "/register", data={"csrf_token": csrf_token_register}
    )
    register_data = get_register_data(response_register_post.data)

    # Enable account.
    with app.app_context():
        account = (
            db.session.query(Account)
            .filter(Account.account == register_data["account"])
            .first()
        )
        account.is_enabled = True
        db.session.commit()

    # Get csrf_token from /login
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    # Login.
    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": register_data["username"],
            "password": register_data["password"],
            "key": (BytesIO(bytes(register_data["key"], "utf-8")), "data.key"),
            "csrf_token": csrf_token_login,
        },
    )
    assert response.status_code == 302

    # Check that we are logged in.
    response = client.get("/settings")
    assert (
        b"Logged in on account: " + bytes(register_data["account"], "utf-8")
        in response.data
    )
    assert (
        b"Logged in as user: " + bytes(register_data["username"], "utf-8")
        in response.data
    )
    assert b"Is account enabled: Yes" in response.data


def test_login_post_no_data(client):
    """Test login with empty form data

    This test verifies that the login endpoint properly validates required
    form fields and rejects authentication attempts with empty username,
    password, or key file data.
    """
    # Get csrf_token from /login
    response = client.get("/login")
    csrf_token = get_csrf_token(response.data)

    # Test POST /login with no data.
    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": "",
            "password": "",
            "key": (BytesIO(b""), "data.key"),
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 200
    assert b"Login error" in response.data
    assert (
        b"Failed to login, wrong username and/or password and/or key." in response.data
    )


def test_login_post_wrong_password(client):
    """Test login with incorrect password

    This test verifies that the application properly validates passwords
    during login attempts and rejects authentication with incorrect passwords
    or passwords that fail validation, returning appropriate error messages.
    """
    # Get the csrf token for /register
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    # Register account and user
    response_register_post = client.post(
        "/register", data={"csrf_token": csrf_token_register}
    )
    register_data = get_register_data(response_register_post.data)

    # Get csrf_token from /login
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    # Test wrong password.
    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": register_data["username"],
            "password": "wrongpassword",
            "key": (BytesIO(bytes(register_data["key"], "utf-8")), "data.key"),
            "csrf_token": csrf_token_login,
        },
    )
    assert response.status_code == 200
    assert b"Login error" in response.data
    assert (
        b"Failed to login, wrong username and/or password and/or key." in response.data
    )

    # Test password that fails validation.
    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": register_data["username"],
            "password": "''",
            "key": (BytesIO(bytes(register_data["key"], "utf-8")), "data.key"),
            "csrf_token": csrf_token_login,
        },
    )
    assert response.status_code == 200
    assert b"Login error" in response.data
    assert (
        b"Failed to login, wrong username and/or password and/or key." in response.data
    )


def test_login_post_wrong_username(client, app):
    """Test login with incorrect username

    This test verifies that the application properly validates usernames
    during login attempts and rejects authentication with non-existent usernames
    or usernames that fail validation, returning appropriate error messages.
    """
    # Get the csrf token for /register
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    # Register account and user
    response_register_post = client.post(
        "/register", data={"csrf_token": csrf_token_register}
    )
    register_data = get_register_data(response_register_post.data)

    # Enable account.
    with app.app_context():
        account = (
            db.session.query(Account)
            .filter(Account.account == register_data["account"])
            .first()
        )
        account.is_enabled = True
        db.session.commit()

    # Get csrf_token from /login
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    # Test username that is not in db.
    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": "AAAAAAAAAAAA",
            "password": register_data["password"],
            "key": (BytesIO(bytes(register_data["key"], "utf-8")), "data.key"),
            "csrf_token": csrf_token_login,
        },
    )
    assert response.status_code == 200
    assert b"Login error" in response.data
    assert (
        b"Failed to login, wrong username and/or password and/or key." in response.data
    )

    # Test username that fails validation.
    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": "AAAAAAAAAAAAa",
            "password": register_data["password"],
            "key": (BytesIO(bytes(register_data["key"], "utf-8")), "data.key"),
            "csrf_token": csrf_token_login,
        },
    )
    assert response.status_code == 200
    assert b"Login error" in response.data
    assert (
        b"Failed to login, wrong username and/or password and/or key." in response.data
    )


def test_login_post_wrong_key(client, app):
    """Test login with incorrect key file

    This test verifies that the application properly validates key files
    during login attempts and rejects authentication with incorrect key content
    or keys that fail validation, returning appropriate error messages.
    """
    # Get the csrf token for /register
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    # Register account and user
    response_register_post = client.post(
        "/register", data={"csrf_token": csrf_token_register}
    )
    register_data = get_register_data(response_register_post.data)

    # Enable account.
    with app.app_context():
        account = (
            db.session.query(Account)
            .filter(Account.account == register_data["account"])
            .first()
        )
        account.is_enabled = True
        db.session.commit()

    # Get csrf_token from /login
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    # Test key that fails validation.
    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": register_data["username"],
            "password": register_data["password"],
            "key": (
                BytesIO(bytes(register_data["key"] + "A", "utf-8")),
                "data.key",
            ),
            "csrf_token": csrf_token_login,
        },
    )
    assert response.status_code == 200
    assert b"Login error" in response.data
    assert (
        b"Failed to login, wrong username and/or password and/or key." in response.data
    )

    # Test wrong key.
    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": register_data["username"],
            "password": register_data["password"],
            "key": (BytesIO(bytes("A" * 4096, "utf-8")), "data.key"),
            "csrf_token": csrf_token_login,
        },
    )
    assert response.status_code == 200
    assert b"Login error" in response.data
    assert (
        b"Failed to login, wrong username and/or password and/or key." in response.data
    )


def test_register_post_CSRF(client):
    """Test registration CSRF protection

    This test verifies that the registration endpoint properly enforces CSRF
    protection by rejecting POST requests with invalid CSRF tokens,
    returning a 400 status code for security.
    """
    # Test that we get 400 if the csrf_token is not correct.
    assert client.post("/register", data={"csrf_token": "test"}).status_code == 400


def test_register_post(client):
    """Test successful account registration

    This test verifies that the registration endpoint successfully creates
    new accounts and users, returning proper account credentials including
    account ID, username, password, and key information.
    """
    # Get csrf_token from /register.
    response_get = client.get("/register")
    csrf_token = get_csrf_token(response_get.data)

    # Test that we get satatus code 200
    assert client.post("/register", data={"csrf_token": csrf_token}).status_code == 200

    # Test that we get the account and user information.
    response = client.post("/register", data={"csrf_token": csrf_token})
    assert b"<p>Account:" in response.data
    assert b"<p>Username:" in response.data
    assert b"<p>Password:" in response.data
    assert b'<button type="submit">Download Keyfile</button>' in response.data


def test_register_login_post(client, app):
    """Test complete registration and login flow

    This test verifies the complete user journey from account registration
    through successful login, ensuring that newly registered accounts can
    authenticate properly and access protected resources.
    """
    # Get the csrf token for /register
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    # Register account and user
    response_register_post = client.post(
        "/register", data={"csrf_token": csrf_token_register}
    )
    response = response_register_post

    # Get account
    m = re.search(b"<p>Account: (.*)</p>", response.data)
    account = m.group(1).decode("utf-8")

    # Get username
    m = re.search(b"<p>Username: (.*)</p>", response.data)
    username = m.group(1).decode("utf-8")

    # Get password
    m = re.search(b"<p>Password: (.*)</p>", response.data)
    password = m.group(1).decode("utf-8")

    # Get key
    m = re.search(b'        value="(.*)"', response.data)
    key = m.group(1).decode("utf-8")

    # Get csrf_token from /login
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    # Test login with newly registred account and user.
    assert (
        client.post(
            "/login",
            buffered=True,
            content_type="multipart/form-data",
            data={
                "user": username,
                "password": password,
                "key": (BytesIO(bytes(key, "utf-8")), "data.key"),
                "csrf_token": csrf_token_login,
            },
        ).status_code
        == 302
    )

    # Test login with newly registred account and user, check that account and username is correct and that account is disabled.
    response_login_post = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": username,
            "password": password,
            "key": (BytesIO(bytes(key, "utf-8")), "data.key"),
            "csrf_token": csrf_token_login,
        },
        follow_redirects=True,
    )
    assert (
        b"Logged in on account: " + bytes(account, "utf-8") in response_login_post.data
    )
    assert b"Logged in as user: " + bytes(username, "utf-8") in response_login_post.data
    assert b"Is account enabled: No" in response_login_post.data

    # Test wrong username.
    response_login_post = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": "test",
            "password": password,
            "key": (BytesIO(bytes(key, "utf-8")), "data.key"),
            "csrf_token": csrf_token_login,
        },
        follow_redirects=True,
    )
    assert b"Login error" in response_login_post.data
    assert (
        b"Failed to login, wrong username and/or password and/or key."
        in response_login_post.data
    )

    # Test wrong password.
    response_login_post = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": username,
            "password": "test",
            "key": (BytesIO(bytes(key, "utf-8")), "data.key"),
            "csrf_token": csrf_token_login,
        },
        follow_redirects=True,
    )
    assert b"Login error" in response_login_post.data
    assert (
        b"Failed to login, wrong username and/or password and/or key."
        in response_login_post.data
    )

    # Test wrong key.
    response_login_post = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": username,
            "password": password,
            "key": (BytesIO(bytes("test", "utf-8")), "data.key"),
            "csrf_token": csrf_token_login,
        },
        follow_redirects=True,
    )
    assert b"Login error" in response_login_post.data
    assert (
        b"Failed to login, wrong username and/or password and/or key."
        in response_login_post.data
    )


def test_logout_get(client):
    """Test logout functionality

    This test verifies that the logout endpoint properly handles user
    logout requests by redirecting users and clearing their session,
    ensuring users are properly logged out and redirected to the home page.
    """
    # Test that we get redirected.
    assert client.get("/logout").status_code == 302

    # Test that we are not logged in.
    response = client.get("/logout", follow_redirects=True)
    assert b"Logged in on account: Not logged in" in response.data
    assert b"Logged in as user: Not logged in" in response.data


def test_register_login_settings_logout(client, app):
    """Test complete user workflow from registration to logout

    This test verifies the entire user lifecycle including registration,
    login, accessing protected settings page, and proper logout functionality
    with session cleanup and redirection.
    """
    # Get the csrf token for /register
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    # Register account and user
    response_register_post = client.post(
        "/register", data={"csrf_token": csrf_token_register}
    )
    register_data = get_register_data(response_register_post.data)

    # Get csrf_token from /login
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    # Test /login with newly registred account and user.
    assert (
        client.post(
            "/login",
            buffered=True,
            content_type="multipart/form-data",
            data={
                "user": register_data["username"],
                "password": register_data["password"],
                "key": (
                    BytesIO(bytes(register_data["key"], "utf-8")),
                    "data.key",
                ),
                "csrf_token": csrf_token_login,
            },
        ).status_code
        == 302
    )

    # Test /login with newly registred account and user, check that account and username is correct and that account is disabled.
    response_login_post = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": register_data["username"],
            "password": register_data["password"],
            "key": (BytesIO(bytes(register_data["key"], "utf-8")), "data.key"),
            "csrf_token": csrf_token_login,
        },
        follow_redirects=True,
    )
    assert (
        b"Logged in on account: " + bytes(register_data["account"], "utf-8")
        in response_login_post.data
    )
    assert (
        b"Logged in as user: " + bytes(register_data["username"], "utf-8")
        in response_login_post.data
    )
    assert b"Is account enabled: No" in response_login_post.data

    # Test /settings.
    assert client.get("/settings").status_code == 200
    response_settings_get = client.get("/settings")
    assert (
        b"Logged in on account: " + bytes(register_data["account"], "utf-8")
        in response_settings_get.data
    )
    assert (
        b"Logged in as user: " + bytes(register_data["username"], "utf-8")
        in response_settings_get.data
    )
    assert b"Is account enabled: No" in response_settings_get.data

    # Test /logout that we get redirected.
    assert client.get("/logout").status_code == 302

    # Test /logout that we are not logged in.
    response = client.get("/logout", follow_redirects=True)
    assert b"Logged in on account: Not logged in" in response.data

    # Test that we cant se the data from /settings.
    assert client.get("/settings").status_code == 302
    response_settings_get2 = client.get("/settings")
    assert (
        b"Logged in on account: " + bytes(register_data["account"], "utf-8")
        not in response_settings_get2.data
    )
    assert (
        b"Logged in as user: " + bytes(register_data["username"], "utf-8")
        not in response_settings_get2.data
    )
    assert b"Is account enabled: No" not in response_settings_get2.data
    assert b"Change password on user" not in response_settings_get2.data

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = (
            db.session.query(User)
            .filter(User.user == register_data["username"])
            .first()
        )
        db.session.query(Authenticated).filter(
            Authenticated.user_id == user_from_db.id
        ).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(
            Account.account == register_data["account"]
        ).delete()
        db.session.commit()


def test_is_athenticated(client, app):
    """Test authentication validation with valid session cookie

    This test verifies that the is_athenticated function correctly validates
    session cookies and returns appropriate user objects for authenticated
    sessions while properly handling various authentication scenarios.
    """
    # Get the csrf token for /register
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    # Register account and user
    response_register_post = client.post(
        "/register", data={"csrf_token": csrf_token_register}
    )
    register_data = get_register_data(response_register_post.data)

    # Get csrf_token from /login
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    # Test POST /login with newly registered account and user.
    assert (
        client.post(
            "/login",
            buffered=True,
            content_type="multipart/form-data",
            data={
                "user": register_data["username"],
                "password": register_data["password"],
                "key": (
                    BytesIO(bytes(register_data["key"], "utf-8")),
                    "data.key",
                ),
                "csrf_token": csrf_token_login,
            },
        ).status_code
        == 302
    )

    # Test POST /login with newly registered account and user, check that account and username is correct and that account is disabled.
    response_login_post = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": register_data["username"],
            "password": register_data["password"],
            "key": (BytesIO(bytes(register_data["key"], "utf-8")), "data.key"),
            "csrf_token": csrf_token_login,
        },
        follow_redirects=True,
    )
    assert (
        b"Logged in on account: " + bytes(register_data["account"], "utf-8")
        in response_login_post.data
    )
    assert (
        b"Logged in as user: " + bytes(register_data["username"], "utf-8")
        in response_login_post.data
    )
    assert b"Is account enabled: No" in response_login_post.data

    # Test that is_athenticated return None when cookie do not excist in db.
    with app.app_context():
        assert is_athenticated("test") == None

    # Test that is_athenticated return None when cookie has illigal char.
    with app.app_context():
        assert is_athenticated("''") == None

    # Test that is_athenticated cookie is linked to correct user.
    session_secret = ""
    with client:
        client.post(
            "/login",
            buffered=True,
            content_type="multipart/form-data",
            data={
                "user": register_data["username"],
                "password": register_data["password"],
                "key": (
                    BytesIO(bytes(register_data["key"], "utf-8")),
                    "data.key",
                ),
                "csrf_token": csrf_token_login,
            },
            follow_redirects=True,
        )
        session_secret = session["secret"]

    with app.app_context():
        assert is_athenticated(session_secret) != None
        user_from_is_athenticated = is_athenticated(session_secret)
        assert user_from_is_athenticated.user == register_data["username"]

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = (
            db.session.query(User)
            .filter(User.user == register_data["username"])
            .first()
        )
        db.session.query(Authenticated).filter(
            Authenticated.user_id == user_from_db.id
        ).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(
            Account.account == register_data["account"]
        ).delete()
        db.session.commit()


def test_generate_token_requirements():
    """Test token generation consistency across multiple lengths

    This test verifies that the generate_token function consistently produces
    valid tokens across different lengths, ensuring all character composition
    and security requirements are met for each generated token.
    """
    for length in [6, 8, 12, 16]:
        token = generate_token(length)
        assert len(token) == length

        # Check that all characters are uppercase or digits
        for char in token:
            assert char.isupper() or char.isdigit()

        # Check that it has at least one uppercase letter
        assert any(c.isupper() for c in token)

        # Check that it has at least 4 digits
        assert sum(c.isdigit() for c in token) >= 4


def test_generate_password_requirements():
    """Test password generation consistency across multiple lengths

    This test verifies that the generate_password function consistently produces
    valid passwords across different lengths, ensuring all security requirements
    including character diversity and minimum digit counts are met.
    """
    for length in [10, 20, 24, 50]:
        password = generate_password(length)
        assert len(password) == length

        # Check that all characters are letters or digits
        for char in password:
            assert char.isalnum()

        # Check that it has at least one lowercase letter
        assert any(c.islower() for c in password)

        # Check that it has at least one uppercase letter
        assert any(c.isupper() for c in password)

        # Check that it has at least 3 digits
        assert sum(c.isdigit() for c in password) >= 3


def test_is_athenticated_invalid_cookie(app):
    """Test authentication validation with invalid cookie formats

    This test verifies that the is_athenticated function properly rejects
    various invalid cookie formats including None values, empty strings,
    and cookies containing illegal characters that could pose security risks.
    """
    with app.app_context():
        # Test with empty string
        assert is_athenticated("") == None

        # Test with invalid characters
        assert is_athenticated("invalid'chars") == None
        assert is_athenticated("test<script>") == None
        assert is_athenticated("cookie with spaces") == None

        # Test with None (now handled properly in auth.py)
        assert is_athenticated(None) == None


def test_is_athenticated_expired_cookie(client, app):
    """Test authentication rejection for expired session cookies

    This test verifies that the is_athenticated function properly handles
    expired authentication cookies by returning None when the cookie's
    valid_to timestamp has passed the current time.
    """
    # Register and login first
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    response_register_post = client.post(
        "/register", data={"csrf_token": csrf_token_register}
    )
    register_data = get_register_data(response_register_post.data)

    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    # Login to create authenticated session
    session_secret = ""
    with client:
        client.post(
            "/login",
            buffered=True,
            content_type="multipart/form-data",
            data={
                "user": register_data["username"],
                "password": register_data["password"],
                "key": (BytesIO(bytes(register_data["key"], "utf-8")), "data.key"),
                "csrf_token": csrf_token_login,
            },
        )
        session_secret = session["secret"]

    # Manually expire the cookie by updating the database
    with app.app_context():
        from datetime import datetime, timedelta

        authenticated = Authenticated.query.filter_by(cookie=session_secret).first()
        authenticated.valid_to = datetime.now() - timedelta(hours=1)
        db.session.commit()

        # Now test that expired cookie returns None
        assert is_athenticated(session_secret) == None

        # Clean up
        user_from_db = (
            db.session.query(User)
            .filter(User.user == register_data["username"])
            .first()
        )
        db.session.query(Authenticated).filter(
            Authenticated.user_id == user_from_db.id
        ).delete()
        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.query(Account).filter(
            Account.account == register_data["account"]
        ).delete()
        db.session.commit()


def test_download_keyfile_get_method(client):
    """Test keyfile download endpoint HTTP method restriction

    This test verifies that the download_keyfile endpoint properly enforces
    POST-only access by rejecting GET requests with a 405 Method Not Allowed
    status code for security and API design compliance.
    """
    response = client.get("/download_keyfile")
    assert response.status_code == 405  # Method not allowed


def test_download_keyfile_empty_data(client):
    """Test keyfile download validation with empty password key

    This test verifies that the download_keyfile endpoint properly validates
    required form data and returns appropriate error messages when the
    password_key field is empty or missing.
    """
    response_register_get = client.get("/register")
    csrf_token = get_csrf_token(response_register_get.data)

    response = client.post(
        "/download_keyfile", data={"password_key": "", "csrf_token": csrf_token}
    )
    assert response.status_code == 200
    assert b"Download keyfile error" in response.data
    assert b"Failed to download keyfile, data is missing" in response.data


def test_download_keyfile_whitespace_only(client):
    """Test keyfile download validation with whitespace-only input

    This test verifies that the download_keyfile endpoint properly handles
    whitespace-only input by treating it as empty data and returning
    appropriate validation error messages.
    """
    response_register_get = client.get("/register")
    csrf_token = get_csrf_token(response_register_get.data)

    response = client.post(
        "/download_keyfile",
        data={"password_key": "   \t\n  ", "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert b"Download keyfile error" in response.data
    assert b"Failed to download keyfile, data is missing" in response.data


def test_download_keyfile_invalid_password_key(client):
    """Test keyfile download validation with malformed password key

    This test verifies that the download_keyfile endpoint properly validates
    password key format and rejects keys containing invalid characters
    that could pose security risks or fail validation.
    """
    response_register_get = client.get("/register")
    csrf_token = get_csrf_token(response_register_get.data)

    response = client.post(
        "/download_keyfile",
        data={"password_key": "invalid'key<script>", "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert b"Download keyfile error" in response.data
    assert b"failed to download keyfile, validation failed" in response.data


def test_download_keyfile_success(client):
    """Test successful keyfile download with valid credentials

    This test verifies that the download_keyfile endpoint correctly processes
    valid password keys and returns the key file with proper HTTP headers
    for file download including content type and attachment disposition.
    """
    # First register to get a valid key
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    response_register_post = client.post(
        "/register", data={"csrf_token": csrf_token_register}
    )
    register_data = get_register_data(response_register_post.data)

    # Get csrf token for download_keyfile
    csrf_token = get_csrf_token(response_register_get.data)

    # Now download the keyfile
    response = client.post(
        "/download_keyfile",
        data={"password_key": register_data["key"], "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert response.headers["Content-Disposition"] == "attachment; filename=ddmail.key"
    assert response.data == register_data["key"].encode("utf-8")


def test_login_validation_failures(client):
    """Test login form input validation error handling

    This test verifies that the login endpoint properly validates all form
    inputs including username and password formats, rejecting requests with
    invalid characters and returning appropriate error messages.
    """
    response_login_get = client.get("/login")
    csrf_token = get_csrf_token(response_login_get.data)

    # Test with invalid username
    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": "invalid'user<script>",
            "password": "ValidPass123",
            "key": (BytesIO(b"valid key content"), "data.key"),
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 200
    assert b"Login error" in response.data
    assert (
        b"Failed to login, wrong username and/or password and/or key" in response.data
    )

    # Test with invalid password
    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": "validuser",
            "password": "invalid'pass<script>",
            "key": (BytesIO(b"valid key content"), "data.key"),
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 200
    assert b"Login error" in response.data


def test_login_user_not_found(client):
    """Test login attempt with non-existent username

    This test verifies that the login endpoint properly handles authentication
    attempts for usernames that do not exist in the database, returning
    generic error messages to prevent username enumeration attacks.
    """
    response_login_get = client.get("/login")
    csrf_token = get_csrf_token(response_login_get.data)

    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": "NONEXISTENTUSER123",
            "password": "ValidPassword123",
            "key": (BytesIO(b"valid key content here"), "data.key"),
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 200
    assert b"Login error" in response.data
    assert (
        b"Failed to login, wrong username and/or password and/or key" in response.data
    )


def test_login_password_verification_error(client, app):
    """Test password verification error handling during login

    This test verifies that the login endpoint properly handles password
    verification failures using Argon2 password hashing, ensuring that
    VerifyMismatchError exceptions are caught and handled appropriately.
    """
    # First register a user
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    response_register_post = client.post(
        "/register", data={"csrf_token": csrf_token_register}
    )
    register_data = get_register_data(response_register_post.data)

    # Try to login with wrong password
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": register_data["username"],
            "password": "WrongPassword123",
            "key": (BytesIO(bytes(register_data["key"], "utf-8")), "data.key"),
            "csrf_token": csrf_token_login,
        },
    )
    assert response.status_code == 200
    assert b"Login error" in response.data
    assert (
        b"Failed to login, wrong username and/or password and/or key" in response.data
    )

    # Clean up
    with app.app_context():
        user_from_db = (
            db.session.query(User)
            .filter(User.user == register_data["username"])
            .first()
        )
        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.query(Account).filter(
            Account.account == register_data["account"]
        ).delete()
        db.session.commit()


def test_login_key_verification_error(client, app):
    """Test key file verification error handling during login

    This test verifies that the login endpoint properly validates key files
    and handles verification failures when the provided key does not match
    the stored key hash for the user account.
    """
    # First register a user
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    response_register_post = client.post(
        "/register", data={"csrf_token": csrf_token_register}
    )
    register_data = get_register_data(response_register_post.data)

    # Try to login with wrong key
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    wrong_key = "W" * 4096  # Wrong key with correct length
    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": register_data["username"],
            "password": register_data["password"],
            "key": (BytesIO(bytes(wrong_key, "utf-8")), "data.key"),
            "csrf_token": csrf_token_login,
        },
    )
    assert response.status_code == 200
    assert b"Login error" in response.data
    assert (
        b"Failed to login, wrong username and/or password and/or key" in response.data
    )

    # Clean up
    with app.app_context():
        user_from_db = (
            db.session.query(User)
            .filter(User.user == register_data["username"])
            .first()
        )
        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.query(Account).filter(
            Account.account == register_data["account"]
        ).delete()
        db.session.commit()


def test_logout_without_session(client):
    """Test logout behavior for unauthenticated users

    This test verifies that the logout endpoint properly handles requests
    from users who are not logged in, redirecting them appropriately
    without causing errors or security issues.
    """
    response = client.get("/logout")
    assert response.status_code == 302  # Redirect to home


def test_logout_with_invalid_session(client):
    """Test logout behavior with invalid session data

    This test verifies that the logout endpoint properly handles requests
    with invalid or corrupted session secrets, cleaning up gracefully
    and redirecting users to the home page.
    """
    with client.session_transaction() as sess:
        sess["secret"] = "invalid_secret"

    response = client.get("/logout")
    assert response.status_code == 302  # Redirect to home


def test_register_post_creates_account_user(client, app):
    """Test database record creation during registration

    This test verifies that the registration endpoint properly creates
    and commits account and user records to the database with correct
    relationships and default values for new accounts.
    """
    response_register_get = client.get("/register")
    csrf_token = get_csrf_token(response_register_get.data)

    response = client.post("/register", data={"csrf_token": csrf_token})
    assert response.status_code == 200
    register_data = get_register_data(response.data)

    # Verify account and user were created in database
    with app.app_context():
        account = (
            db.session.query(Account)
            .filter(Account.account == register_data["account"])
            .first()
        )
        assert account is not None
        assert account.is_enabled == False
        assert account.is_gratis == False
        assert account.funds_in_sek == 0
        assert account.total_storage_space_g == 0

        user = (
            db.session.query(User)
            .filter(User.user == register_data["username"])
            .first()
        )
        assert user is not None
        assert user.account_id == account.id

        # Clean up
        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.query(Account).filter(
            Account.account == register_data["account"]
        ).delete()
        db.session.commit()


def test_login_missing_partial_data(client):
    """Test login form validation with partially missing data

    This test verifies that the login endpoint properly validates all
    required form fields and returns appropriate error messages when
    individual fields like username, password, or key file are missing.
    """
    response_login_get = client.get("/login")
    csrf_token = get_csrf_token(response_login_get.data)

    # Missing username
    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": "",
            "password": "ValidPassword123",
            "key": (BytesIO(b"valid key content"), "data.key"),
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 200
    assert b"Login error" in response.data

    # Missing password
    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": "validuser",
            "password": "",
            "key": (BytesIO(b"valid key content"), "data.key"),
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 200
    assert b"Login error" in response.data

    # Missing key file
    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": "validuser",
            "password": "ValidPassword123",
            "key": (BytesIO(b""), "data.key"),
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 200
    assert b"Login error" in response.data


def test_generate_token_edge_cases():
    """Test token generation edge cases and boundary conditions

    This test verifies that the generate_token function handles edge cases
    correctly including minimum and maximum practical lengths while
    consistently meeting security requirements for character composition.
    """
    # Test with minimum practical length that can satisfy requirements
    token = generate_token(5)
    assert len(token) == 5
    assert any(c.isupper() for c in token)  # Must have at least one uppercase
    assert sum(c.isdigit() for c in token) >= 4  # Must have at least 4 digits

    # Test with longer length
    token = generate_token(20)
    assert len(token) == 20
    assert any(c.isupper() for c in token)
    assert sum(c.isdigit() for c in token) >= 4


def test_generate_password_edge_cases():
    """Test password generation edge cases and boundary conditions

    This test verifies that the generate_password function handles edge cases
    correctly including minimum practical lengths while consistently meeting
    all security requirements across multiple generations.
    """
    # Test with minimum practical length that can satisfy requirements
    password = generate_password(6)
    assert len(password) == 6
    assert any(c.islower() for c in password)
    assert any(c.isupper() for c in password)
    assert sum(c.isdigit() for c in password) >= 3

    # Test multiple generations to ensure consistency
    for _ in range(5):
        password = generate_password(12)
        assert len(password) == 12
        assert any(c.islower() for c in password)
        assert any(c.isupper() for c in password)
        assert sum(c.isdigit() for c in password) >= 3


def test_is_athenticated_nonexistent_cookie(app):
    """Test authentication with valid format but unrecognized cookie

    This test verifies that the is_athenticated function properly handles
    cookies that have valid formatting but do not exist in the authenticated
    sessions database table, returning None for security.
    """
    with app.app_context():
        # Test with valid format cookie that doesn't exist in database
        nonexistent_cookie = "A" * 128  # Valid format but not in DB
        assert is_athenticated(nonexistent_cookie) == None


def test_login_whitespace_handling(client):
    """Test login form whitespace handling and input sanitization

    This test verifies that the login endpoint properly handles whitespace
    in form inputs by trimming leading and trailing spaces and validating
    the sanitized input against security requirements.
    """
    response_login_get = client.get("/login")
    csrf_token = get_csrf_token(response_login_get.data)

    # Test username with leading/trailing whitespace
    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": "  validuser  ",
            "password": "ValidPassword123",
            "key": (BytesIO(b"valid key content"), "data.key"),
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 200
    assert b"Login error" in response.data

    # Test password with whitespace
    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": "validuser",
            "password": "  ValidPassword123  ",
            "key": (BytesIO(b"valid key content"), "data.key"),
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 200
    assert b"Login error" in response.data


def test_logout_authenticated_user_cleanup(client, app):
    """Test authenticated session cleanup during logout

    This test verifies that the logout endpoint properly removes authenticated
    session records from the database when users log out, preventing
    orphaned sessions and ensuring proper security cleanup.
    """
    # First register and login
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    response_register_post = client.post(
        "/register", data={"csrf_token": csrf_token_register}
    )
    register_data = get_register_data(response_register_post.data)

    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    # Login
    session_secret = ""
    with client:
        client.post(
            "/login",
            buffered=True,
            content_type="multipart/form-data",
            data={
                "user": register_data["username"],
                "password": register_data["password"],
                "key": (BytesIO(bytes(register_data["key"], "utf-8")), "data.key"),
                "csrf_token": csrf_token_login,
            },
        )
        session_secret = session["secret"]

    # Verify authenticated entry exists
    with app.app_context():
        authenticated = Authenticated.query.filter_by(cookie=session_secret).first()
        assert authenticated is not None
        user_id = authenticated.user_id

    # Logout
    with client:
        response = client.get("/logout")
        assert response.status_code == 302

    # Verify authenticated entry was removed
    with app.app_context():
        authenticated = Authenticated.query.filter_by(user_id=user_id).first()
        assert authenticated is None

        # Clean up remaining data
        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.query(Account).filter(
            Account.account == register_data["account"]
        ).delete()
        db.session.commit()


def test_download_keyfile_missing_form_field(client):
    """Test keyfile download with missing form field

    This test verifies that the download_keyfile endpoint properly handles
    requests where the password_key form field is completely missing,
    returning appropriate HTTP error codes for malformed requests.
    """
    response_register_get = client.get("/register")
    csrf_token = get_csrf_token(response_register_get.data)

    # Post without password_key field
    response = client.post("/download_keyfile", data={"csrf_token": csrf_token})
    assert response.status_code == 400  # Bad request due to missing field


def test_register_post_database_commit_verification(client, app):
    """Test database transaction completion during registration

    This test verifies that the registration endpoint properly commits
    database transactions and that all account and user data is persisted
    correctly with proper relationships and generated tokens.
    """
    with app.app_context():
        # Check initial state
        initial_account_count = db.session.query(Account).count()
        initial_user_count = db.session.query(User).count()

    response_register_get = client.get("/register")
    csrf_token = get_csrf_token(response_register_get.data)

    response = client.post("/register", data={"csrf_token": csrf_token})
    register_data = get_register_data(response.data)

    with app.app_context():
        # Verify counts increased
        assert db.session.query(Account).count() == initial_account_count + 1
        assert db.session.query(User).count() == initial_user_count + 1

        # Verify specific data
        account = Account.query.filter_by(account=register_data["account"]).first()
        user = User.query.filter_by(user=register_data["username"]).first()

        assert account.payment_token is not None
        assert len(account.payment_token) == 12
        assert user.account_id == account.id

        # Clean up
        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.query(Account).filter(
            Account.account == register_data["account"]
        ).delete()
        db.session.commit()


def test_is_athenticated_valid_cookie_valid_user(client, app):
    """Test successful authentication with valid session cookie

    This test verifies that the is_athenticated function correctly returns
    user objects for valid, non-expired session cookies and provides
    access to related account information through proper relationships.
    """
    # Setup - register and login
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    response_register_post = client.post(
        "/register", data={"csrf_token": csrf_token_register}
    )
    register_data = get_register_data(response_register_post.data)

    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    session_secret = ""
    with client:
        client.post(
            "/login",
            buffered=True,
            content_type="multipart/form-data",
            data={
                "user": register_data["username"],
                "password": register_data["password"],
                "key": (BytesIO(bytes(register_data["key"], "utf-8")), "data.key"),
                "csrf_token": csrf_token_login,
            },
        )
        session_secret = session["secret"]

    # Test is_athenticated returns correct user
    with app.app_context():
        authenticated_user = is_athenticated(session_secret)
        assert authenticated_user is not None
        assert authenticated_user.user == register_data["username"]
        assert hasattr(authenticated_user, "account")
        assert authenticated_user.account.account == register_data["account"]

        # Clean up
        user_id = authenticated_user.id
        db.session.query(Authenticated).filter(
            Authenticated.user_id == user_id
        ).delete()
        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.query(Account).filter(
            Account.account == register_data["account"]
        ).delete()
        db.session.commit()


def test_login_successful_cookie_generation(client, app):
    """Test session cookie generation and storage during successful login

    This test verifies that successful login attempts generate secure session
    cookies with proper length and expiration times, storing authenticated
    session records in the database with correct timestamps.
    """
    # Register first
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    response_register_post = client.post(
        "/register", data={"csrf_token": csrf_token_register}
    )
    register_data = get_register_data(response_register_post.data)

    # Login
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    session_secret = ""
    with client:
        response = client.post(
            "/login",
            buffered=True,
            content_type="multipart/form-data",
            data={
                "user": register_data["username"],
                "password": register_data["password"],
                "key": (BytesIO(bytes(register_data["key"], "utf-8")), "data.key"),
                "csrf_token": csrf_token_login,
            },
        )
        assert response.status_code == 302  # Redirect to /settings
        session_secret = session["secret"]

    # Verify cookie properties
    assert len(session_secret) == 128  # Password length for cookie

    # Verify database entry
    with app.app_context():
        authenticated = Authenticated.query.filter_by(cookie=session_secret).first()
        assert authenticated is not None
        user = User.query.get(authenticated.user_id)
        assert user.user == register_data["username"]

        # Verify expiration time is set (should be 3 hours from now)
        from datetime import datetime, timedelta

        expected_expiry = datetime.now() + timedelta(hours=3)
        actual_expiry = datetime.strptime(
            str(authenticated.valid_to), "%Y-%m-%d %H:%M:%S"
        )
        # Allow 1 minute tolerance for test execution time
        assert abs((expected_expiry - actual_expiry).total_seconds()) < 60

        # Clean up
        db.session.query(Authenticated).filter(
            Authenticated.user_id == authenticated.user_id
        ).delete()
        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.query(Account).filter(
            Account.account == register_data["account"]
        ).delete()
        db.session.commit()


def test_login_file_upload_edge_cases(client):
    """Test login key file upload validation edge cases

    This test verifies that the login endpoint properly handles various
    key file upload scenarios including files with only whitespace content
    and ensures proper validation error handling.
    """
    response_login_get = client.get("/login")
    csrf_token = get_csrf_token(response_login_get.data)

    # Test with file that has whitespace content
    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": "validuser",
            "password": "ValidPassword123",
            "key": (BytesIO(b"   \t\n   "), "data.key"),
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 200
    assert b"Login error" in response.data


def test_generate_token_multiple_iterations():
    """Test token generation loop behavior and consistency

    This test verifies that the generate_token function's while loop logic
    works correctly across multiple iterations and consistently produces
    tokens that meet all security requirements regardless of random generation.
    """
    # This test ensures the while loop logic is covered
    # by testing multiple generations and verifying requirements
    for _ in range(10):
        token = generate_token(8)
        assert len(token) == 8
        # Must have uppercase letters
        assert any(c.isupper() for c in token)
        # Must have at least 4 digits
        assert sum(c.isdigit() for c in token) >= 4
        # All characters must be uppercase or digits
        assert all(c.isupper() or c.isdigit() for c in token)


def test_generate_password_multiple_iterations():
    """Test password generation loop behavior and consistency

    This test verifies that the generate_password function's while loop logic
    works correctly across multiple iterations and consistently produces
    passwords that meet all security requirements regardless of random generation.
    """
    # This test ensures the while loop logic is covered
    for _ in range(10):
        password = generate_password(15)
        assert len(password) == 15
        # Must have lowercase letters
        assert any(c.islower() for c in password)
        # Must have uppercase letters
        assert any(c.isupper() for c in password)
        # Must have at least 3 digits
        assert sum(c.isdigit() for c in password) >= 3
        # All characters must be alphanumeric
        assert all(c.isalnum() for c in password)


def test_is_athenticated_datetime_parsing(client, app):
    """Test session expiration datetime handling and validation

    This test verifies that the is_athenticated function properly parses
    and compares datetime objects for session expiration validation,
    ensuring accurate time-based authentication decisions.
    """
    # Register and login to create authenticated entry
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    response_register_post = client.post(
        "/register", data={"csrf_token": csrf_token_register}
    )
    register_data = get_register_data(response_register_post.data)

    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    session_secret = ""
    with client:
        client.post(
            "/login",
            buffered=True,
            content_type="multipart/form-data",
            data={
                "user": register_data["username"],
                "password": register_data["password"],
                "key": (BytesIO(bytes(register_data["key"], "utf-8")), "data.key"),
                "csrf_token": csrf_token_login,
            },
        )
        session_secret = session["secret"]

    # Test with valid (not expired) cookie
    with app.app_context():
        authenticated_user = is_athenticated(session_secret)
        assert authenticated_user is not None
        assert authenticated_user.user == register_data["username"]

        # Clean up
        user_id = authenticated_user.id
        db.session.query(Authenticated).filter(
            Authenticated.user_id == user_id
        ).delete()
        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.query(Account).filter(
            Account.account == register_data["account"]
        ).delete()
        db.session.commit()


def test_login_form_validation_coverage(client):
    """Test comprehensive login form validation coverage

    This test verifies that all form validation paths in the login endpoint
    are properly tested, including key file content validation and error
    message consistency across different validation failure scenarios.
    """
    response_login_get = client.get("/login")
    csrf_token = get_csrf_token(response_login_get.data)

    # Test key file validation failure
    response = client.post(
        "/login",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "user": "VALIDUSER123",
            "password": "ValidPassword123",
            "key": (BytesIO(b"invalid<key>content"), "data.key"),
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 200
    assert b"Login error" in response.data
    assert (
        b"Failed to login, wrong username and/or password and/or key" in response.data
    )


def test_register_response_content_verification(client):
    """Test registration response content completeness

    This test verifies that the registration endpoint returns all required
    user credentials and form elements in the response, including account
    details, generated passwords, and keyfile download functionality.
    """
    response_register_get = client.get("/register")
    csrf_token = get_csrf_token(response_register_get.data)

    response = client.post("/register", data={"csrf_token": csrf_token})
    assert response.status_code == 200

    # Verify all expected content is present
    assert b"Account:" in response.data
    assert b"Username:" in response.data
    assert b"Password:" in response.data
    assert b'name="password_key"' in response.data  # Form field for key download

    register_data = get_register_data(response.data)

    # Verify data format
    assert len(register_data["account"]) == 12
    assert len(register_data["username"]) == 12
    assert len(register_data["password"]) == 24
    assert len(register_data["key"]) == 4096


def test_logout_session_clearing(client):
    """Test complete session data clearing during logout

    This test verifies that the logout endpoint properly clears all session
    data from the client session, ensuring no residual authentication
    information remains after logout completion.
    """
    # Set up session data
    with client.session_transaction() as sess:
        sess["secret"] = "test_secret"
        sess["other_data"] = "should_be_cleared"

    response = client.get("/logout")
    assert response.status_code == 302

    # Verify session is cleared
    with client.session_transaction() as sess:
        assert len(sess) == 0


def test_download_keyfile_content_type_and_headers(client):
    """Test keyfile download HTTP headers and content type

    This test verifies that the download_keyfile endpoint sets appropriate
    HTTP headers including content type, content disposition for file download,
    and returns the correct key file content in the response body.
    """
    # Register to get a valid key
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    response_register_post = client.post(
        "/register", data={"csrf_token": csrf_token_register}
    )
    register_data = get_register_data(response_register_post.data)

    # Get csrf token for download_keyfile
    csrf_token = get_csrf_token(response_register_get.data)

    # Download keyfile
    response = client.post(
        "/download_keyfile",
        data={"password_key": register_data["key"], "csrf_token": csrf_token},
    )

    assert response.status_code == 200
    assert response.mimetype == "text/plain"
    assert "attachment" in response.headers.get("Content-Disposition", "")
    assert "filename=ddmail.key" in response.headers.get("Content-Disposition", "")
    assert response.data.decode("utf-8") == register_data["key"]


def test_is_athenticated_cookie_validation_edge_cases(app):
    """Test authentication validation with edge case valid cookie formats

    This test verifies that the is_athenticated function properly handles
    cookies that pass basic format validation but represent edge cases
    such as minimum or maximum length valid cookies that don't exist in database.
    """
    with app.app_context():
        # Test with minimum length valid cookie
        valid_format_cookie = "A" * 10  # Short but valid format
        assert is_athenticated(valid_format_cookie) == None

        # Test with maximum reasonable length
        long_valid_cookie = "A" * 1000
        assert is_athenticated(long_valid_cookie) == None
