import pytest
import re
from io import BytesIO
from flask import session
from werkzeug.http import parse_cookie
from tests.helpers import get_csrf_token
from tests.helpers import get_register_data
from ddmail_webapp.auth import is_athenticated, generate_password, generate_token
from ddmail_webapp.models import db, Account, Email, Account_domain, Alias, Global_domain, User, Authenticated
import ddmail_validators.validators as validators

def test_generate_password():
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
    # Test that we get 400 if the csrf_token is not set.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':'test', 'password':'test', 'key':(BytesIO(b'FILE CONTENT'), 'data.key')}).status_code == 400
    
    # Test that we get the string "The CSRF token i missing" if the csrf_token is not set.
    response = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':'test', 'password':'test', 'key':(BytesIO(b'FILE CONTENT'), 'data.key')})
    assert b"The CSRF token is missing" in response.data

def test_login_post(client,app):
    # Get the csrf token for /register
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    # Register account and user
    response_register_post = client.post("/register", data={'csrf_token':csrf_token_register})
    register_data = get_register_data(response_register_post.data)

    # Enable account.
    with app.app_context():
        account = db.session.query(Account).filter(Account.account == register_data["account"]).first()
        account.is_enabled = True        
        db.session.commit()

    # Get csrf_token from /login
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    # Login.
    response = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login})
    assert response.status_code == 302
    
    # Check that we are logged in.
    response = client.get("/settings")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response.data
    assert b"Is account enabled: Yes" in response.data

def test_login_post_no_data(client,app):
    # Get the csrf token for /register
    response_login = client.get("/login")
    csrf_token_login = get_csrf_token(response_login.data)
    
    response = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':"", 'password':"", 'key':(BytesIO(bytes("", 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login})
    assert response.status_code == 200
    assert b"Login error" in response.data
    assert b"Failed to login, wrong username and/or password and/or key." in response.data

def test_login_post_wrong_password(client,app):
    # Get the csrf token for /register
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    # Register account and user
    response_register_post = client.post("/register", data={'csrf_token':csrf_token_register})
    register_data = get_register_data(response_register_post.data)

    # Enable account.
    with app.app_context():
        account = db.session.query(Account).filter(Account.account == register_data["account"]).first()
        account.is_enabled = True        
        db.session.commit()

    # Get csrf_token from /login
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    # Test wrong password.
    response = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':"AAAAAAAAAAAAAAAAAAAAAAAA", 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login})
    assert response.status_code == 200
    assert b"Login error" in response.data
    assert b"Failed to login, wrong username and/or password and/or key." in response.data
    
    # Test password that fails validation.
    response = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':"AAAAAAAAAAAAAAAAAAAAAAA-", 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login})
    assert response.status_code == 200
    assert b"Login error" in response.data
    assert b"Failed to login, wrong username and/or password and/or key." in response.data

def test_login_post_wrong_username(client,app):
    # Get the csrf token for /register
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    # Register account and user
    response_register_post = client.post("/register", data={'csrf_token':csrf_token_register})
    register_data = get_register_data(response_register_post.data)

    # Enable account.
    with app.app_context():
        account = db.session.query(Account).filter(Account.account == register_data["account"]).first()
        account.is_enabled = True        
        db.session.commit()

    # Get csrf_token from /login
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    # Test username that is not in db.
    response = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':"AAAAAAAAAAAA", 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login})
    assert response.status_code == 200
    assert b"Login error" in response.data
    assert b"Failed to login, wrong username and/or password and/or key." in response.data
    
    # Test username that fails validation.
    response = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':"AAAAAAAAAAAAa", 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login})
    assert response.status_code == 200
    assert b"Login error" in response.data
    assert b"Failed to login, wrong username and/or password and/or key." in response.data

def test_login_post_wrong_key(client,app):
    # Get the csrf token for /register
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    # Register account and user
    response_register_post = client.post("/register", data={'csrf_token':csrf_token_register})
    register_data = get_register_data(response_register_post.data)

    # Enable account.
    with app.app_context():
        account = db.session.query(Account).filter(Account.account == register_data["account"]).first()
        account.is_enabled = True        
        db.session.commit()

    # Get csrf_token from /login
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    # Test key that fails validation.
    response = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"] + "A", 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login})
    assert response.status_code == 200
    assert b"Login error" in response.data
    assert b"Failed to login, wrong username and/or password and/or key." in response.data

    # Test wrong key.
    response = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes("A"*4096, 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login})
    assert response.status_code == 200
    assert b"Login error" in response.data
    assert b"Failed to login, wrong username and/or password and/or key." in response.data


def test_register_post_CSRF(client):
    # Test that we get 400 if the csrf_token is not correct.
    assert client.post("/register", data={'csrf_token':'test'}).status_code == 400

def test_register_post(client):
    # Get the csrf token.
    response_get = client.get("/register")
    csrf_token = get_csrf_token(response_get.data)

    # Test that we get satatus code 200
    assert client.post("/register", data={'csrf_token':csrf_token}).status_code == 200

    # Test that we get the account and user information.
    response = client.post("/register", data={'csrf_token':csrf_token})
    assert b"Account:" in response.data
    assert b"Username:" in response.data
    assert b"Password:" in response.data
    assert b"Key file content:" in response.data

def test_register_login_post(client):
    # Get the csrf token for /register
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    # Register account and user
    response_register_post = client.post("/register", data={'csrf_token':csrf_token_register})
    response = response_register_post

    # Get account
    m = re.search(b'<p>Account: (.*)</p>', response.data)
    account = m.group(1).decode("utf-8")

    # Get username
    m = re.search(b'<p>Username: (.*)</p>', response.data)
    username = m.group(1).decode("utf-8")

    #Get password
    m = re.search(b'<p>Password: (.*)</p>', response.data)
    password = m.group(1).decode("utf-8")

    #Get key
    m = re.search(b'<p>Key file content: (.*)</p>', response.data)
    key = m.group(1).decode("utf-8")
    
    # Get csrf_token from /login
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    # Test login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':username, 'password':password, 'key':(BytesIO(bytes(key, 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302

    # Test login with newly registred account and user, check that account and username is correct and that account is disabled.
    response_login_post = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':username, 'password':password, 'key':(BytesIO(bytes(key, 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}, follow_redirects=True)
    assert b"Logged in on account: " + bytes(account, 'utf-8') in response_login_post.data
    assert b"Logged in as user: " + bytes(username, 'utf-8') in response_login_post.data
    assert b"Is account enabled: No" in response_login_post.data
    
    # Test wrong username.
    response_login_post = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':'test', 'password':password, 'key':(BytesIO(bytes(key, 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}, follow_redirects=True)
    assert b"Login error" in response_login_post.data
    assert b"Failed to login, wrong username and/or password and/or key." in response_login_post.data

    # Test wrong password.
    response_login_post = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':username, 'password':'test', 'key':(BytesIO(bytes(key, 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}, follow_redirects=True)
    assert b"Login error" in response_login_post.data
    assert b"Failed to login, wrong username and/or password and/or key." in response_login_post.data

    # Test wrong key.
    response_login_post = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':username, 'password':password, 'key':(BytesIO(bytes("test", 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}, follow_redirects=True)
    assert b"Login error" in response_login_post.data
    assert b"Failed to login, wrong username and/or password and/or key." in response_login_post.data

def test_logout_get(client):
    # Test that we get redirected.
    assert client.get("/logout").status_code == 302

    # Test that we are not logged in.
    response = client.get("/logout",follow_redirects = True)
    assert b"Logged in on account: Not logged in" in response.data
    assert b"Logged in as user: Not logged in" in response.data

def test_register_login_settings_logout(client,app):
    # Get the csrf token for /register
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    # Register account and user
    response_register_post = client.post("/register", data={'csrf_token':csrf_token_register})
    register_data = get_register_data(response_register_post.data)

    # Get csrf_token from /login
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    # Test /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302

    # Test /login with newly registred account and user, check that account and username is correct and that account is disabled.
    response_login_post = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login},follow_redirects = True)
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_login_post.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_login_post.data
    assert b"Is account enabled: No" in response_login_post.data

    # Test /settings.
    assert client.get("/settings").status_code == 200
    response_settings_get = client.get("/settings")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_get.data
    assert b"Is account enabled: No" in response_settings_get.data

    # Test /logout that we get redirected.
    assert client.get("/logout").status_code == 302

    # Test /logout that we are not logged in.
    response = client.get("/logout",follow_redirects = True)
    assert b"Logged in on account: Not logged in" in response.data

    # Test that we cant se the data from /settings.
    assert client.get("/settings").status_code == 302
    response_settings_get2 = client.get("/settings")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') not in response_settings_get2.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') not in response_settings_get2.data
    assert b"Is account enabled: No" not in response_settings_get2.data
    assert b"Change password on user" not in response_settings_get2.data

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()

def test_is_athenticated(client,app):
    # Get the csrf token for /register
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    # Register account and user
    response_register_post = client.post("/register", data={'csrf_token':csrf_token_register})
    register_data = get_register_data(response_register_post.data)

    # Get csrf_token from /login
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    # Test POST /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302

    # Test POST /login with newly registred account and user, check that account and username is correct and that account is disabled.
    response_login_post = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login},follow_redirects = True)
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_login_post.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_login_post.data
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
        client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login},follow_redirects = True)
        session_secret = session["secret"]

    with app.app_context():
        assert is_athenticated(session_secret) != None
        user_from_is_athenticated = is_athenticated(session_secret)
        assert user_from_is_athenticated.user == register_data["username"]

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()
