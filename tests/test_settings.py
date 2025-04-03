import pytest
import re
import datetime
from io import BytesIO
from tests.helpers import get_csrf_token
from tests.helpers import get_register_data
from ddmail_webapp.models import db, Account, Email, Account_domain, Alias, Global_domain, User, Authenticated

def test_settings_disabled_account(client,app):
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

    # Test GET /settings.
    assert client.get("/settings").status_code == 200
    response_settings_get = client.get("/settings")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_get.data
    assert b"Is account enabled: No" in response_settings_get.data

def test_settings_enabled_account(client,app):
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

    # Test POST /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302

    # Test POST /login with newly registred account and user, check that account and username is correct and that account is disabled.
    response_login_post = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login},follow_redirects = True)
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_login_post.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_login_post.data
    assert b"Is account enabled: Yes" in response_login_post.data

    # Test GET /settings.
    assert client.get("/settings").status_code == 200
    response_settings_get = client.get("/settings")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_get.data
    assert b"Is account enabled: Yes" in response_settings_get.data

def test_settings_disabled_account_payment_token(client, app):
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

    # Test GET /settings/payment_token.
    assert client.get("/settings/payment_token").status_code == 200
    response_settings_payment_token_get = client.get("/settings/payment_token")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_payment_token_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_payment_token_get.data
    assert b"Is account enabled: No" in response_settings_payment_token_get.data
    assert b"Payment token for this accounts:" in response_settings_payment_token_get.data

def test_settings_disabled_account_change_password_on_user(client, app):
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

    # Test GET /settings/change_password_on_user.
    assert client.get("/settings/change_password_on_user").status_code == 200
    response_settings_change_password_on_user_get = client.get("/settings/change_password_on_user")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_change_password_on_user_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_change_password_on_user_get.data
    assert b"Is account enabled: No" in response_settings_change_password_on_user_get.data
    assert b"Failed to change users password beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu." in response_settings_change_password_on_user_get.data

def test_settings_enabled_account_change_password_on_user(client, app):
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

    # Test POST /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302

    # Test GET /settings/change_password_on_user.
    assert client.get("/settings/change_password_on_user").status_code == 200
    response_settings_change_password_on_user_get = client.get("/settings/change_password_on_user")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_change_password_on_user_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_change_password_on_user_get.data
    assert b"Is account enabled: Yes" in response_settings_change_password_on_user_get.data
    assert b"Change password" in response_settings_change_password_on_user_get.data

    # Get csrf_token from /settings/change_password_on_user
    csrf_token_settings_change_password_on_user = get_csrf_token(response_settings_change_password_on_user_get.data)

    # Test wrong csrf_token on /settings/change_password_on_user
    assert client.post("/settings/change_password_on_user", data={'csrf_token':"wrong csrf_token"}).status_code == 400

    # Test empty csrf_token on /settings/change_password_on_user
    response_settings_change_password_on_user_empty_csrf_post = client.post("/settings/change_password_on_user", data={'csrf_token':""})
    assert b"The CSRF token is missing" in response_settings_change_password_on_user_empty_csrf_post.data

    # Test POST /settings/change-password_on_user
    response_settings_change_password_on_user_post = client.post("/settings/change_password_on_user", data={'csrf_token':csrf_token_settings_change_password_on_user})
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_change_password_on_user_post.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_change_password_on_user_post.data
    assert b"Is account enabled: Yes" in response_settings_change_password_on_user_post.data
    assert b"Successfully changed password on user: " + bytes(register_data["username"], 'utf-8') in response_settings_change_password_on_user_post.data

    # Get new password.
    m = re.search(b'to new password: (.*)</p>', response_settings_change_password_on_user_post.data)
    new_user_password = m.group(1).decode("utf-8")

    # Logout current user /logout
    assert client.get("/logout").status_code == 302

    # Test that user is not logged in.
    assert client.get("/").status_code == 200
    response_main_get = client.get("/")
    assert b"Logged in on account: Not logged in" in response_main_get.data
    assert b"Logged in as user: Not logged in" in response_main_get.data
    assert b"Main" in response_main_get.data
    assert b"Login" in response_main_get.data
    assert b"Register" in response_main_get.data
    assert b"About" in response_main_get.data

    # Get csrf_token from /login
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    # Test POST /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':new_user_password, 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302

    # Test POST /login with newly registred account and user, check that account and username is correct and that account is enabled.
    response_login_post = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':new_user_password, 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login},follow_redirects = True)
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_login_post.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_login_post.data
    assert b"Is account enabled: Yes" in response_login_post.data

def test_settings_disabled_change_key_on_user(client,app):
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

    # Test GET /settings/change_key_on_user
    assert client.get("/settings/change_key_on_user").status_code == 200
    response_settings_change_key_on_user_get = client.get("/settings/change_key_on_user")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_change_key_on_user_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_change_key_on_user_get.data
    assert b"Is account enabled: No" in response_settings_change_key_on_user_get.data
    assert b"Failed to change users key beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu." in response_settings_change_key_on_user_get.data

def test_settings_enabled_account_change_key_on_user(client, app):
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

    # Test POST /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302

    # Test GET /settings/change_key_on_user.
    assert client.get("/settings/change_key_on_user").status_code == 200
    response_settings_change_key_on_user_get = client.get("/settings/change_key_on_user")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_change_key_on_user_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_change_key_on_user_get.data
    assert b"Is account enabled: Yes" in response_settings_change_key_on_user_get.data
    assert b"Change password" in response_settings_change_key_on_user_get.data

    # Get csrf_token from /settings/change_key_on_user
    csrf_token_settings_change_key_on_user = get_csrf_token(response_settings_change_key_on_user_get.data)

    # Test wrong csrf_token on /settings/change_key_on_user
    assert client.post("/settings/change_key_on_user", data={'csrf_token':"wrong csrf_token"}).status_code == 400

    # Test empty csrf_token on /settings/change_key_on_user
    response_settings_change_key_on_user_empty_csrf_post = client.post("/settings/change_key_on_user", data={'csrf_token':""})
    assert b"The CSRF token is missing" in response_settings_change_key_on_user_empty_csrf_post.data

    # Test POST /settings/change_key_on_user
    response_settings_change_key_on_user_post = client.post("/settings/change_key_on_user", data={'csrf_token':csrf_token_settings_change_key_on_user})
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_change_key_on_user_post.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_change_key_on_user_post.data
    assert b"Is account enabled: Yes" in response_settings_change_key_on_user_post.data
    assert b"Successfully changed key on user: " + bytes(register_data["username"], 'utf-8') in response_settings_change_key_on_user_post.data

    # Get new key.
    m = re.search(b'to new key: (.*)</p>', response_settings_change_key_on_user_post.data)
    new_user_key = m.group(1).decode("utf-8")

    # Logout current user /logout
    assert client.get("/logout").status_code == 302

    # Test that user is not logged in.
    assert client.get("/").status_code == 200
    response_main_get = client.get("/")
    assert b"Logged in on account: Not logged in" in response_main_get.data
    assert b"Logged in as user: Not logged in" in response_main_get.data
    assert b"Main" in response_main_get.data
    assert b"Login" in response_main_get.data
    assert b"Register" in response_main_get.data
    assert b"About" in response_main_get.data

    # Get csrf_token from /login
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    # Test POST /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(new_user_key, 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302

    # Test GET /settings/change_key_on_user.
    assert client.get("/settings").status_code == 200
    response_settings_get = client.get("/settings")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_get.data
    assert b"Is account enabled: Yes" in response_settings_get.data
    assert b"Change password" in response_settings_get.data
        
def test_settings_disabled_account_add_user_to_account(client,app):
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

    # Test GET /settings/add_user_to_account.
    assert client.get("/settings/add_user_to_account").status_code == 200
    response_settings_add_user_to_account_get = client.get("/settings/add_user_to_account")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_user_to_account_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_user_to_account_get.data
    assert b"Is account enabled: No" in response_settings_add_user_to_account_get.data
    assert b"Failed to add user beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu." in response_settings_add_user_to_account_get.data

def test_settings_enabled_account_add_user_to_account(client,app):
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

    # Test POST /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302

    # Test GET /settings/add_user_to_account.
    assert client.get("/settings/add_user_to_account").status_code == 200
    response_settings_add_user_to_account_get = client.get("/settings/add_user_to_account")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_user_to_account_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_user_to_account_get.data
    assert b"Is account enabled: Yes" in response_settings_add_user_to_account_get.data
    assert b"<h2>Add new user to account</h2>" in response_settings_add_user_to_account_get.data

    # Get csrf_token from /settings/add_user_to_account
    csrf_token_settings_add_user_to_account = get_csrf_token(response_settings_add_user_to_account_get.data)

    # Test wrong csrf_token on /settings/change_key_on_user
    assert client.post("/settings/add_user_to_account", data={'csrf_token':"wrong csrf_token"}).status_code == 400

    # Test empty csrf_token on /settings/change_key_on_user
    response_settings_add_user_to_account_empty_csrf_post = client.post("/settings/add_user_to_account", data={'csrf_token':""})
    assert b"The CSRF token is missing" in response_settings_add_user_to_account_empty_csrf_post.data

    # Test POST /settings/add_user_to_account
    response_settings_add_user_to_account_post = client.post("/settings/add_user_to_account", data={'csrf_token':csrf_token_settings_add_user_to_account})
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_user_to_account_post.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_user_to_account_post.data
    assert b"Is account enabled: Yes" in response_settings_add_user_to_account_post.data
    assert b"<h2>Added new user to account</h2>" in response_settings_add_user_to_account_post.data
    
    # Get the new user information
    new_user_data = get_register_data(response_settings_add_user_to_account_post.data)

    # Logout current user /logout
    assert client.get("/logout").status_code == 302

    # Test that user is not logged in.
    assert client.get("/").status_code == 200
    response_main_get = client.get("/")
    assert b"Logged in on account: Not logged in" in response_main_get.data
    assert b"Logged in as user: Not logged in" in response_main_get.data
    assert b"Main" in response_main_get.data
    assert b"Login" in response_main_get.data
    assert b"Register" in response_main_get.data
    assert b"About" in response_main_get.data

    # Get csrf_token from /login
    response_login_get = client.get("/login")
    csrf_token_login = get_csrf_token(response_login_get.data)

    # Test POST /login with newly registred user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':new_user_data["username"], 'password':new_user_data["password"], 'key':(BytesIO(bytes(new_user_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302

    # Test GET /settings and test that we are logged in wiht the new user on the same account as before.
    assert client.get("/settings").status_code == 200
    response_settings_get = client.get("/settings")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_get.data
    assert b"Logged in on account: " + bytes(new_user_data["account"], 'utf-8') in response_settings_get.data
    assert b"Logged in as user: " + bytes(new_user_data["username"], 'utf-8') in response_settings_get.data
    assert b"Is account enabled: Yes" in response_settings_get.data
    
def test_settings_disabled_account_show_account_users(client,app):
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

    # Test GET /settings/show_account_users.
    assert client.get("/settings/show_account_users").status_code == 200
    response_settings_show_account_users_get = client.get("/settings/show_account_users")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_show_account_users_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_show_account_users_get.data
    assert b"Is account enabled: No" in response_settings_show_account_users_get.data
    assert b"Failed to show account users beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu." in response_settings_show_account_users_get.data
        
def test_settings_enabled_account_show_account_users(client,app):
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

    # Test POST /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302

    # Test GET /settings/show_account_users.
    assert client.get("/settings/show_account_users").status_code == 200
    response_settings_show_account_users_get = client.get("/settings/show_account_users")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_show_account_users_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_show_account_users_get.data
    assert b"Is account enabled: Yes" in response_settings_show_account_users_get.data
    assert b"<h3>Show Account Users</h3>" in response_settings_show_account_users_get.data
    assert b"Current active users for this account:\n\n<br>\n" + bytes(register_data["username"], 'utf-8') in response_settings_show_account_users_get.data

def test_settings_disabled_account_remove_account_user(client,app):
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

    # Test GET /settings/remove_account_user.
    assert client.get("/settings/remove_account_user").status_code == 200
    response_settings_remove_account_user_get = client.get("/settings/remove_account_user")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_remove_account_user_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_remove_account_user_get.data
    assert b"Is account enabled: No" in response_settings_remove_account_user_get.data
    assert b"Failed to remove account user beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu." in response_settings_remove_account_user_get.data

def test_settings_enabled_account_remove_account_user(client,app):
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

    # Test POST /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302

    #
    #
    # Test GET /settings/remove_account_user.
    assert client.get("/settings/remove_account_user").status_code == 200
    response_settings_remove_account_user_get = client.get("/settings/remove_account_user")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_remove_account_user_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_remove_account_user_get.data
    assert b"Is account enabled: Yes" in response_settings_remove_account_user_get.data
    assert b"<h3>Remove Account user</h3>" in response_settings_remove_account_user_get.data

    # Get csrf_token from /settings/change_key_on_user
    csrf_token_settings_remove_account_user = get_csrf_token(response_settings_remove_account_user_get.data)

    #
    #
    # Test wrong csrf_token on /settings/remove_account_user
    assert client.post("/settings/remove_account_user", data={'csrf_token':"wrong csrf_token"}).status_code == 400

    #
    #
    # Test empty csrf_token on /settings/remove_account_user
    response_settings_remove_account_user_empty_csrf_post = client.post("/settings/remove_account_user", data={'csrf_token':""})
    assert b"The CSRF token is missing" in response_settings_remove_account_user_empty_csrf_post.data

    #
    #
    # Test to remove the same user as the logged in user.
    response_settings_remove_account_user_post = client.post("/settings/remove_account_user", data={'remove_user':register_data["username"],'csrf_token':csrf_token_register})
    assert b"<h3>Remove user error</h3>" in response_settings_remove_account_user_post.data
    assert b"Failed to remove account user, you can not remove the same user as you are logged in as." in response_settings_remove_account_user_post.data

    #
    #
    # Test to remove a user belonging to someone else account.
    # Get the csrf token for /register
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    # Register new account with a new user
    response_register_post = client.post("/register", data={'csrf_token':csrf_token_register})
    new_account_data = get_register_data(response_register_post.data)

    # Test to remove a user from another account.
    response_settings_remove_account_user_post = client.post("/settings/remove_account_user", data={'remove_user':new_account_data["username"],'csrf_token':csrf_token_register})
    assert b"<h3>Remove user error</h3>" in response_settings_remove_account_user_post.data
    assert b"Failed to removed account user, validation failed." in response_settings_remove_account_user_post.data

    #
    #
    # Test to remove a user that do not exist.
    response_settings_remove_account_user_post = client.post("/settings/remove_account_user", data={'remove_user':"USER01",'csrf_token':csrf_token_register})
    assert b"<h3>Remove user error</h3>" in response_settings_remove_account_user_post.data
    assert b"Failed to removed account user, illigal character in string." in response_settings_remove_account_user_post.data

    #
    #
    # Test to remove a user that is empty string.
    response_settings_remove_account_user_post = client.post("/settings/remove_account_user", data={'remove_user':"",'csrf_token':csrf_token_register})
    assert b"<h3>Remove user error</h3>" in response_settings_remove_account_user_post.data
    assert b"Failed to removed account user, illigal character in string." in response_settings_remove_account_user_post.data

    #
    #
    # Test to remove a user with sqli chars in the name.
    response_settings_remove_account_user_post = client.post("/settings/remove_account_user", data={'remove_user':"\'",'csrf_token':csrf_token_register})
    assert b"<h3>Remove user error</h3>" in response_settings_remove_account_user_post.data
    assert b"Failed to removed account user, illigal character in string." in response_settings_remove_account_user_post.data

    #
    #
    # Test to remove a user from our account.
     
    # Add a new user.
    assert client.get("/settings/add_user_to_account").status_code == 200
    response_settings_add_user_to_account_get = client.get("/settings/add_user_to_account")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_user_to_account_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_user_to_account_get.data
    assert b"Is account enabled: Yes" in response_settings_add_user_to_account_get.data
    assert b"<h2>Add new user to account</h2>" in response_settings_add_user_to_account_get.data

    # Get csrf_token from /settings/add_user_to_account
    csrf_token_settings_add_user_to_account = get_csrf_token(response_settings_add_user_to_account_get.data)

    # Test POST /settings/add_user_to_account
    response_settings_add_user_to_account_post = client.post("/settings/add_user_to_account", data={'csrf_token':csrf_token_settings_add_user_to_account})
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_user_to_account_post.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_user_to_account_post.data
    assert b"Is account enabled: Yes" in response_settings_add_user_to_account_post.data
    assert b"<h2>Added new user to account</h2>" in response_settings_add_user_to_account_post.data
    
    # Get the new user information
    new_user_data = get_register_data(response_settings_add_user_to_account_post.data)

    # Remove newly created user.
    response_settings_remove_account_user_post = client.post("/settings/remove_account_user", data={'remove_user':new_user_data["username"],'csrf_token':csrf_token_register})
    assert b"<h3>Remove user</h3" in response_settings_remove_account_user_post.data
    assert b"Successfully removed user." in response_settings_remove_account_user_post.data
      
def test_settings_disabled_account_add_email(client,app):
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

    # Test GET /settings/add_email.
    assert client.get("/settings/add_email").status_code == 200
    response_settings_add_email_get = client.get("/settings/add_email")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_email_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_email_get.data
    assert b"Is account enabled: No" in response_settings_add_email_get.data
    assert b"Failed to add email beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu." in response_settings_add_email_get.data

def test_settings_enabled_account_add_email(client,app):
    # Add global domain used in test.
    with app.app_context():
        does_it_exist = db.session.query(Global_domain).filter(Global_domain.domain == "globaltestdomain01.se", Global_domain.is_enabled == 1).count()
        if does_it_exist == 0:
            new_global_domain = Global_domain(domain = "globaltestdomain01.se", is_enabled = 1)
            db.session.add(new_global_domain)
            db.session.commit()
        
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

    # Test POST /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302

    # Test GET /settings/add_email.
    assert client.get("/settings/add_email").status_code == 200
    response_settings_add_email_get = client.get("/settings/add_email")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_email_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_email_get.data
    assert b"Is account enabled: Yes" in response_settings_add_email_get.data

    # Get csrf_token from /settings/change_key_on_user
    csrf_token_settings_add_email = get_csrf_token(response_settings_add_email_get.data)

    #
    #
    # Test wrong csrf_token on /settings/add_email
    assert client.post("/settings/add_email", data={'domain':"globaltestdomain01.se", 'email':"test01", 'csrf_token':"wrong csrf_token"}).status_code == 400

    #
    #
    # Test empty csrf_token on /settings/add_email
    response_settings_add_email_empty_csrf_post = client.post("/settings/add_email", data={'domain':"globaltestdomain01", 'email':"test01" ,'csrf_token':""})
    assert b"The CSRF token is missing" in response_settings_add_email_empty_csrf_post.data
    
    #
    #
    # Test to add email account with a global domain.
    
    #
    #
    # Test to add two emails acounts that has the same name.

    #
    #
    # Test to add email account with a account domain.

    #
    #
    # Test to add email account with a account domain that belongs to a different account.

    #
    #
    # Test to add email account with char that is not allowed.
    response_settings_add_email_post = client.post("/settings/add_email", data={'domain':"globaltestdomain01.se", 'email':"test01\"", 'csrf_token':csrf_token_settings_add_email})
    assert b"<h3>Add email error</h3>" in response_settings_add_email_post.data
    assert b"Failed to add email, email validation failed." in response_settings_add_email_post.data

    #
    #
    # Test to add email account that has the same name as on email account that belongs to a different account.

    #
    #
    # Test to add email account that has to long name.

    #
    #
    # Test to add email account that has empty string. 
    response_settings_add_email_post = client.post("/settings/add_email", data={'domain':"globaltestdomain01.se", 'email':"", 'csrf_token':csrf_token_settings_add_email})
    assert b"<h3>Add email error</h3>" in response_settings_add_email_post.data
    assert b"Failed to add email, csrf validation failed." in response_settings_add_email_post.data

def test_settings_disabled_account_show_email(client,app):
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

    # Test GET /settings/show_email
    assert client.get("/settings/show_email").status_code == 200
    response_settings_show_email_get = client.get("/settings/show_email")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_show_email_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_show_email_get.data
    assert b"Is account enabled: No" in response_settings_show_email_get.data
    assert b"Failed to show email beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu." in response_settings_show_email_get.data

def test_settings_enabled_account_show_email(client,app):
    # Add global domain used in test.
    with app.app_context():
        does_it_exist = db.session.query(Global_domain).filter(Global_domain.domain == "globaltestdomain01.se", Global_domain.is_enabled == 1).count()
        if does_it_exist == 0:
            new_global_domain = Global_domain(domain = "globaltestdomain01.se", is_enabled = 1)
            db.session.add(new_global_domain)
            db.session.commit()
                
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

    # Test POST /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302
    
    # Test GET /settings/add_email.
    assert client.get("/settings/add_email").status_code == 200
    response_settings_add_email_get = client.get("/settings/add_email")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_email_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_email_get.data
    assert b"Is account enabled: Yes" in response_settings_add_email_get.data

    # Get csrf_token from /settings/add_email    
    csrf_token_settings_add_email = get_csrf_token(response_settings_add_email_get.data)
   
    # Add email account with a global domain.
    with app.app_context():
        account = db.session.query(Account).filter(Account.account == register_data["account"]).first()
        global_domain = db.session.query(Global_domain).filter(Global_domain.domain == "globaltestdomain01.se").first()
        new_email = Email(account_id = account.id, email = "test01@globaltestdomain01.se", password_hash = "mysecrethash", storage_space_mb = 0, global_domain_id = global_domain.id)
        db.session.add(new_email)
        db.session.commit()

    # Test GET /settings/show_email
    assert client.get("/settings/show_email").status_code == 200
    response_settings_show_email_get = client.get("/settings/show_email")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_show_email_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_show_email_get.data
    assert b"Is account enabled: Yes" in response_settings_show_email_get.data
    assert b"<h3>Show Email Account</h3>" in response_settings_show_email_get.data
    assert b"Current active email accounts for this user:" in response_settings_show_email_get.data
    assert b"test01@globaltestdomain01.se" in response_settings_show_email_get.data

def test_settings_disabled_account_remove_email(client,app):
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
    
    # Test GET /settings/remove_email
    assert client.get("/settings/remove_email").status_code == 200
    response_settings_remove_email_get = client.get("/settings/remove_email")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_remove_email_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_remove_email_get.data
    assert b"Is account enabled: No" in response_settings_remove_email_get.data
    assert b"Failed to remove email beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu." in response_settings_remove_email_get.data

def test_settings_enabled_account_remove_email(client,app):
    # Add global domain used in test.
    with app.app_context():
        does_it_exist = db.session.query(Global_domain).filter(Global_domain.domain == "globaltestdomain01.se", Global_domain.is_enabled == 1).count()
        if does_it_exist == 0:
            new_global_domain = Global_domain(domain = "globaltestdomain01.se", is_enabled = 1)
            db.session.add(new_global_domain)
            db.session.commit()

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

    # Test POST /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302
    
    # Test GET /settings/add_email.
    assert client.get("/settings/add_email").status_code == 200
    response_settings_add_email_get = client.get("/settings/add_email")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_email_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_email_get.data
    assert b"Is account enabled: Yes" in response_settings_add_email_get.data
    
    # Get csrf_token from /settings/add_email    
    csrf_token_settings_add_email = get_csrf_token(response_settings_add_email_get.data)
   
    # Add email account with a global domain.
    with app.app_context():
        account = db.session.query(Account).filter(Account.account == register_data["account"]).first()
        global_domain = db.session.query(Global_domain).filter(Global_domain.domain == "globaltestdomain01.se").first()
        new_email = Email(account_id = account.id, email = "test01@globaltestdomain01.se", password_hash = "mysecrethash", storage_space_mb = 0, global_domain_id = global_domain.id)
        db.session.add(new_email)
        db.session.commit()
    
    # Test GET /settings/show_email
    assert client.get("/settings/show_email").status_code == 200
    response_settings_show_email_get = client.get("/settings/show_email")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_show_email_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_show_email_get.data
    assert b"Is account enabled: Yes" in response_settings_show_email_get.data
    assert b"<h3>Show Email Account</h3>" in response_settings_show_email_get.data
    assert b"Current active email accounts for this user:" in response_settings_show_email_get.data
    assert b"test01@globaltestdomain01.se" in response_settings_show_email_get.data

    # Test GET /settings/remove_email
    assert client.get("/settings/remove_email").status_code == 200
    response_settings_remove_email_get = client.get("/settings/remove_email")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_remove_email_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_remove_email_get.data
    assert b"Is account enabled: Yes" in response_settings_remove_email_get.data
    assert b"<h3>Remove Email Account</h3>" in response_settings_remove_email_get.data
    assert b"test01@globaltestdomain01.se" in response_settings_remove_email_get.data
    
    # Get csrf_token from /settings/remove_email    
    csrf_token_settings_remove_email = get_csrf_token(response_settings_remove_email_get.data)

    #
    #
    # Test to remove email account with a global domain.
    response_settings_remove_email_post = client.post("/settings/remove_email", data={'remove_email':"test01@globaltestdomain01.se", 'csrf_token':csrf_token_settings_remove_email})
    assert b"<h3>Remove email error</h3>" in response_settings_remove_email_post.data
    assert b"Failed to remove data on disc for email account" in response_settings_remove_email_post.data

    # Test GET /settings/show_email
    assert client.get("/settings/show_email").status_code == 200
    response_settings_show_email_get = client.get("/settings/show_email")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_show_email_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_show_email_get.data
    assert b"Is account enabled: Yes" in response_settings_show_email_get.data
    assert b"<h3>Show Email Account</h3>" in response_settings_show_email_get.data
    assert b"Current active email accounts for this user:" in response_settings_show_email_get.data
    assert b"test01@globaltestdomain01.se" not in response_settings_show_email_get.data

    #
    #
    # Test to remove email account with account domain.

    #
    #
    # Test to remove email that do not exist.

    #
    #
    # Test to remove email that belongs to another account.

    #
    #
    # Test to remove email that has a alias.
  

def test_settings_disabled_account_change_password_on_email(client,app):
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

    # Test GET /settings/change_password_on_email
    assert client.get("/settings/change_password_on_email").status_code == 200
    response_settings_change_password_on_email_get = client.get("/settings/change_password_on_email")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_change_password_on_email_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_change_password_on_email_get.data
    assert b"Is account enabled: No" in response_settings_change_password_on_email_get.data
    assert b"Failed to change password on email account beacuse this account is disabled." in response_settings_change_password_on_email_get.data

def test_settings_enabled_account_change_password_on_email(client,app):
    # Add global domain used in test.
    with app.app_context():
        does_it_exist = db.session.query(Global_domain).filter(Global_domain.domain == "globaltestdomain01.se", Global_domain.is_enabled == 1).count()
        if does_it_exist == 0:
            new_global_domain = Global_domain(domain = "globaltestdomain01.se", is_enabled = 1)
            db.session.add(new_global_domain)
            db.session.commit()

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

    # Test POST /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302
    
    # Test GET /settings/add_email.
    assert client.get("/settings/add_email").status_code == 200
    response_settings_add_email_get = client.get("/settings/add_email")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_email_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_email_get.data
    assert b"Is account enabled: Yes" in response_settings_add_email_get.data
    
    # Get csrf_token from /settings/add_email    
    csrf_token_settings_add_email = get_csrf_token(response_settings_add_email_get.data)
   
    # Add email account with a global domain.
    with app.app_context():
        account = db.session.query(Account).filter(Account.account == register_data["account"]).first()
        global_domain = db.session.query(Global_domain).filter(Global_domain.domain == "globaltestdomain01.se").first()
        new_email = Email(account_id = account.id, email = "test01@globaltestdomain01.se", password_hash = "mysecrethash", storage_space_mb = 0, global_domain_id = global_domain.id)
        db.session.add(new_email)
        db.session.commit()
    
    # Test GET /settings/change_password_on_email
    assert client.get("/settings/change_password_on_email").status_code == 200
    response_settings_change_password_on_email_get = client.get("/settings/change_password_on_email")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_change_password_on_email_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_change_password_on_email_get.data
    assert b"Is account enabled: Yes" in response_settings_change_password_on_email_get.data

def test_settings_disabled_account_show_alias(client,app):
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

    # Test GET /settings/show_alias
    assert client.get("/settings/show_alias").status_code == 200
    response_settings_show_alias_get = client.get("/settings/show_alias")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_show_alias_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_show_alias_get.data
    assert b"Is account enabled: No" in response_settings_show_alias_get.data
    assert b"Failed to show alias beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu." in response_settings_show_alias_get.data

def test_settings_enabled_account_show_alias(client,app):
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

    # Test POST /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302

    # Test GET /settings/show_alias
    assert client.get("/settings/show_alias").status_code == 200
    response_settings_show_alias_get = client.get("/settings/show_alias")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_show_alias_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_show_alias_get.data
    assert b"Is account enabled: Yes" in response_settings_show_alias_get.data

def test_settings_disabled_account_add_alias(client,app):
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

    # Test GET /settings/add_alias
    assert client.get("/settings/add_alias").status_code == 200
    response_settings_add_alias_get = client.get("/settings/add_alias")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_alias_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_alias_get.data
    assert b"Is account enabled: No" in response_settings_add_alias_get.data
    assert b"ailed to add alias beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu." in response_settings_add_alias_get.data

def test_settings_enabled_account_add_alias(client,app):
    # Add global domain used in test.
    with app.app_context():
        does_it_exist = db.session.query(Global_domain).filter(Global_domain.domain == "globaltestdomain01.se", Global_domain.is_enabled == 1).count()
        if does_it_exist == 0:
            new_global_domain = Global_domain(domain = "globaltestdomain01.se", is_enabled = 1)
            db.session.add(new_global_domain)
            db.session.commit()

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

    # Test POST /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302

    # Test GET /settings/add_email.
    assert client.get("/settings/add_email").status_code == 200
    response_settings_add_email_get = client.get("/settings/add_email")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_email_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_email_get.data
    assert b"Is account enabled: Yes" in response_settings_add_email_get.data

    # Get csrf_token from /settings/add_email
    csrf_token_settings_add_email = get_csrf_token(response_settings_add_email_get.data)

    # Add email account with a global domain.
    with app.app_context():
        account = db.session.query(Account).filter(Account.account == register_data["account"]).first()
        global_domain = db.session.query(Global_domain).filter(Global_domain.domain == "globaltestdomain01.se").first()
        new_email = Email(account_id = account.id, email = "test01@globaltestdomain01.se", password_hash = "mysecrethash", storage_space_mb = 0, global_domain_id = global_domain.id)
        db.session.add(new_email)
        db.session.commit()

    # Test GET /settings/add_alias
    assert client.get("/settings/add_alias").status_code == 200
    response_settings_add_alias_get = client.get("/settings/add_alias")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_alias_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_alias_get.data
    assert b"Is account enabled: Yes" in response_settings_add_alias_get.data
    
    # Get csrf_token from /settings/add_alias
    csrf_token_settings_add_alias = get_csrf_token(response_settings_add_alias_get.data)

    #
    #
    # Test wrong csrf_token on /settings/add_alias
    assert client.post("/settings/add_alias", data={'domain':"globaltestdomain01.se", 'src':"testalias01", 'dst':"test01@globaltestdomain01.se", 'csrf_token':"wrong csrf_token"}).status_code == 400

    #
    #
    # Test empty csrf_token on /settings/add_alias
    response_settings_add_alias_empty_csrf_post = client.post("/settings/add_alias", data={'domain':"globaltestdomain01.se", 'src':"testalias01" ,'dst':"test01@globaltestdomain01.se",'csrf_token':""})
    assert b"The CSRF token is missing" in response_settings_add_alias_empty_csrf_post.data
    

    #
    #
    # Test to add alias with src global domain and dst global domain
    response_settings_add_alias_post = client.post("/settings/add_alias", data={'domain':"globaltestdomain01.se", 'src':"testalias01" ,'dst':"test01@globaltestdomain01.se",'csrf_token':csrf_token_settings_add_alias})
    assert b"<h3>Add alias</h3>" in response_settings_add_alias_post.data
    assert b"Alias added successfully" in response_settings_add_alias_post.data

def test_settings_disabled_account_remove_alias(client,app):
    # Get the csrf token for /register
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    # Register account and user.
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

    # Test GET /settings/remove_alias
    assert client.get("/settings/remove_alias").status_code == 200
    response_settings_remove_alias_get = client.get("/settings/remove_alias")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_remove_alias_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_remove_alias_get.data
    assert b"Is account enabled: No" in response_settings_remove_alias_get.data
    assert b"Failed to remove alias beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu." in response_settings_remove_alias_get.data

def test_settings_enabled_account_remove_alias(client,app):
    # Add global domain used in test.
    with app.app_context():
        does_it_exist = db.session.query(Global_domain).filter(Global_domain.domain == "globaltestdomain01.se", Global_domain.is_enabled == 1).count()
        if does_it_exist == 0:
            new_global_domain = Global_domain(domain = "globaltestdomain01.se", is_enabled = 1)
            db.session.add(new_global_domain)
            db.session.commit()

    # Get the csrf token for /register
    response_register_get = client.get("/register")
    csrf_token_register = get_csrf_token(response_register_get.data)

    # Register account and user.
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

    # Test POST /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302

    # Test GET /settings/add_email.
    response_settings_add_email_get = client.get("/settings/add_email")
    assert response_settings_add_email_get.status_code == 200
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_email_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_email_get.data
    assert b"Is account enabled: Yes" in response_settings_add_email_get.data

    # Get csrf_token from /settings/change_key_on_user
    csrf_token_settings_add_email = get_csrf_token(response_settings_add_email_get.data)

    # Add email account with a global domain.
    with app.app_context():
        account = db.session.query(Account).filter(Account.account == register_data["account"]).first()
        global_domain = db.session.query(Global_domain).filter(Global_domain.domain == "globaltestdomain01.se").first()
        new_email = Email(account_id = account.id, email = "test01@globaltestdomain01.se", password_hash = "mysecrethash", storage_space_mb = 0, global_domain_id = global_domain.id)
        db.session.add(new_email)
        db.session.commit()
    
    # Test GET /settings/add_alias
    assert client.get("/settings/add_alias").status_code == 200
    response_settings_add_alias_get = client.get("/settings/add_alias")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_alias_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_alias_get.data
    assert b"Is account enabled: Yes" in response_settings_add_alias_get.data
    
    # Get csrf_token from /settings/add_alias
    csrf_token_settings_add_alias = get_csrf_token(response_settings_add_alias_get.data)

    # Test to add alias with src global domain and dst global domain
    response_settings_add_alias_post = client.post("/settings/add_alias", data={'domain':"globaltestdomain01.se", 'src':"testalias01" ,'dst':"test01@globaltestdomain01.se",'csrf_token':csrf_token_settings_add_alias})
    assert b"<h3>Add alias</h3>" in response_settings_add_alias_post.data
    assert b"Alias added successfully" in response_settings_add_alias_post.data

    # Test GET /settings/remove_alias
    response_settings_remove_alias_get = client.get("/settings/remove_alias")
    assert response_settings_remove_alias_get.status_code == 200
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_remove_alias_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_remove_alias_get.data
    assert b"Is account enabled: Yes" in response_settings_remove_alias_get.data
    assert b"<h3>Remove Alias</h3>" in response_settings_remove_alias_get.data

    # Get alias id from form option.
    m = re.search(b'option value="(.*)"', response_settings_remove_alias_get.data) 
    alias_id = m.group(1).decode("utf-8")

    # Get csrf_token from /settings_remove_alias
    csrf_token_settings_remove_alias = get_csrf_token(response_settings_remove_alias_get.data)

    #
    #
    # Test wrong csrf_token on /settings/remove_alias
    assert client.post("/settings/remove_alias", data={'value':alias_id, 'csrf_token':"wrong csrf_token"}).status_code == 400

    #
    #
    # Test empty csrf_token on /settings/remove_alias
    response_settings_remove_alias_empty_csrf_post = client.post("/settings/remove_alias", data={'value':alias_id, 'csrf_token':""})
    assert b"The CSRF token is missing" in response_settings_remove_alias_empty_csrf_post.data

    #
    #
    # Test to remove alias with global domain as dst and src.
    response_settings_remove_alias_post = client.post("/settings/remove_alias", data={'remove_alias':alias_id, 'csrf_token':csrf_token_settings_remove_alias})
    assert response_settings_remove_alias_post.status_code == 200
    assert b"<h3>Remove Alias</h3>" in response_settings_remove_alias_post.data
    assert b"Successfully removed alias." in response_settings_remove_alias_post.data

    #
    #
    # Test to remove empy alias form.
    response_settings_remove_alias_post = client.post("/settings/remove_alias", data={'remove_alias':"", 'csrf_token':csrf_token_settings_remove_alias})
    assert response_settings_remove_alias_post.status_code == 200
    assert b"<h3>Remove Alias Error</h3>" in response_settings_remove_alias_post.data
    assert b"Failed to remove alias, validation failed." in response_settings_remove_alias_post.data

    #
    #
    # Test to remove alias with no alias form var.
    response_settings_remove_alias_post = client.post("/settings/remove_alias", data={'csrf_token':csrf_token_settings_remove_alias})
    assert response_settings_remove_alias_post.status_code == 400

    #
    #
    # Test to remove alias that belongs to another account.

    #
    #
    # Test to remove alias with account domain dst and src.
       
def test_settings_disabled_account_show_domains(client,app):
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

    # Test GET /settings/show_domains
    assert client.get("/settings/show_domains").status_code == 200
    response_settings_show_domains_get = client.get("/settings/show_domains")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_show_domains_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_show_domains_get.data
    assert b"Is account enabled: No" in response_settings_show_domains_get.data
    assert b"Failed to show domains beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu." in response_settings_show_domains_get.data

def test_settings_enabled_account_show_domains(client,app):
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

    # Test POST /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302
    
    # Test GET /settings/add_domain
    response_settings_add_domain_get = client.get("/settings/add_domain")
    assert response_settings_add_domain_get.status_code == 200
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_domain_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_domain_get.data
    assert b"Is account enabled: Yes" in response_settings_add_domain_get.data
    assert b"<h3>Add Domain</h3>" in response_settings_add_domain_get.data
    
    # Get csrf_token from /settings/add_domain
    csrf_token_settings_add_domain = get_csrf_token(response_settings_add_domain_get.data)

    # Test to add account domain
    response_settings_add_domain_post = client.post("/settings/add_domain", data={'domain':"test.ddmail.se", 'csrf_token':csrf_token_settings_add_domain})
    assert response_settings_add_domain_post.status_code == 200
    assert b"<h3>Add Domain</h3>" in response_settings_add_domain_post.data
    assert b"Successfully added domain." in response_settings_add_domain_post.data

    # Test GET /settings/show_domains
    assert client.get("/settings/show_domains").status_code == 200
    response_settings_show_domains_get = client.get("/settings/show_domains")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_show_domains_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_show_domains_get.data
    assert b"Is account enabled: Yes" in response_settings_show_domains_get.data
    assert b"<h3>Show Domains</h3>" in response_settings_show_domains_get.data
    assert b"Current active account domains for this account:" in response_settings_show_domains_get.data
    assert b"test.ddmail.se" in response_settings_show_domains_get.data

def test_settings_disabled_account_add_domain(client,app):
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

    # Test GET /settings/add_domain
    assert client.get("/settings/add_domain").status_code == 200
    response_settings_add_domain_get = client.get("/settings/add_domain")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_domain_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_domain_get.data
    assert b"Is account enabled: No" in response_settings_add_domain_get.data
    assert b"Add domain" in response_settings_add_domain_get.data
    assert b"Failed to add domain beacuse this account is disabled." in response_settings_add_domain_get.data

def test_settings_enabled_account_add_domain(client,app):
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

    # Test POST /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302

    # Test GET /settings/add_domain
    response_settings_add_domain_get = client.get("/settings/add_domain")
    assert response_settings_add_domain_get.status_code == 200
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_domain_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_domain_get.data
    assert b"Is account enabled: Yes" in response_settings_add_domain_get.data
    assert b"<h3>Add Domain</h3>" in response_settings_add_domain_get.data
    
    # Get csrf_token from /settings/add_domain
    csrf_token_settings_add_domain = get_csrf_token(response_settings_add_domain_get.data)

    #
    #
    # Test wrong csrf_token on /settings/add_domain
    assert client.post("/settings/add_domain", data={'domain':"test.ddmail.se", 'csrf_token':"wrong csrf_token"}).status_code == 400

    #
    #
    # Test empty csrf_token on /settings/add_domain
    response_settings_add_domain_empty_csrf_post = client.post("/settings/add_domain", data={'domain':"test.ddmail.se", 'csrf_token':""})
    assert b"The CSRF token is missing" in response_settings_add_domain_empty_csrf_post.data

    #
    #
    # Test to add account domain
    response_settings_add_domain_post = client.post("/settings/add_domain", data={'domain':"test.ddmail.se", 'csrf_token':csrf_token_settings_add_domain})
    assert response_settings_add_domain_post.status_code == 200
    assert b"<h3>Add Domain</h3>" in response_settings_add_domain_post.data
    assert b"Successfully added domain." in response_settings_add_domain_post.data

    #
    #
    # Test to add a domain that already exsist in current/same account 
    response_settings_add_domain_post = client.post("/settings/add_domain", data={'domain':"test.ddmail.se", 'csrf_token':csrf_token_settings_add_domain})
    assert response_settings_add_domain_post.status_code == 200
    assert b"<h3>Add Domain Error</h3>" in response_settings_add_domain_post.data
    assert b"Failed to add domain, the current domain already exist." in response_settings_add_domain_post.data
    
    #
    #
    # Test to add a domain that failes backend validation. 
    response_settings_add_domain_post = client.post("/settings/add_domain", data={'domain':"tes<t.ddmail.se", 'csrf_token':csrf_token_settings_add_domain})
    assert response_settings_add_domain_post.status_code == 200
    assert b"<h3>Add Domain Error</h3>" in response_settings_add_domain_post.data
    assert b"Failed to add domain, domain validation failed." in response_settings_add_domain_post.data

    #
    #
    # Test to add a domain that failes backend validation. 
    response_settings_add_domain_post = client.post("/settings/add_domain", data={'domain':"tes\"t.ddmail.se", 'csrf_token':csrf_token_settings_add_domain})
    assert response_settings_add_domain_post.status_code == 200
    assert b"<h3>Add Domain Error</h3>" in response_settings_add_domain_post.data
    assert b"Failed to add domain, domain validation failed." in response_settings_add_domain_post.data
    
    #
    #
    # Test to add a domain that failes backend validation. 
    response_settings_add_domain_post = client.post("/settings/add_domain", data={'domain':"t--iest.ddmail.se", 'csrf_token':csrf_token_settings_add_domain})
    assert response_settings_add_domain_post.status_code == 200
    assert b"<h3>Add Domain Error</h3>" in response_settings_add_domain_post.data
    assert b"Failed to add domain, domain validation failed." in response_settings_add_domain_post.data
    
    #
    #
    # Test to add a domain that failes backend validation. 
    response_settings_add_domain_post = client.post("/settings/add_domain", data={'domain':"test..ddmail.se", 'csrf_token':csrf_token_settings_add_domain})
    assert response_settings_add_domain_post.status_code == 200
    assert b"<h3>Add Domain Error</h3>" in response_settings_add_domain_post.data
    assert b"Failed to add domain, domain validation failed." in response_settings_add_domain_post.data

    #
    #
    # Test to add a domain that failes backend validation. 
    response_settings_add_domain_post = client.post("/settings/add_domain", data={'domain':"t;est.ddmail.se", 'csrf_token':csrf_token_settings_add_domain})
    assert response_settings_add_domain_post.status_code == 200
    assert b"<h3>Add Domain Error</h3>" in response_settings_add_domain_post.data
    assert b"Failed to add domain, domain validation failed." in response_settings_add_domain_post.data
    
    #
    #
    # Test to add a domain that failes backend validation. 
    response_settings_add_domain_post = client.post("/settings/add_domain", data={'domain':"t\'est.ddmail.se", 'csrf_token':csrf_token_settings_add_domain})
    assert response_settings_add_domain_post.status_code == 200
    assert b"<h3>Add Domain Error</h3>" in response_settings_add_domain_post.data
    assert b"Failed to add domain, domain validation failed." in response_settings_add_domain_post.data
    
    #
    #
    # Test to add a domain that failes form validation. 
    response_settings_add_domain_post = client.post("/settings/add_domain", data={'domain':"a.s", 'csrf_token':csrf_token_settings_add_domain})
    assert response_settings_add_domain_post.status_code == 200
    assert b"<h3>Add Domain Error</h3>" in response_settings_add_domain_post.data
    assert b"Failed to add domain, form validation failed." in response_settings_add_domain_post.data

    
def test_settings_disabled_account_remove_domain(client,app):
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

    # Test GET /settings/remove_domain
    assert client.get("/settings/remove_domain").status_code == 200
    response_settings_remove_domain_get = client.get("/settings/remove_domain")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_remove_domain_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_remove_domain_get.data
    assert b"Is account enabled: No" in response_settings_remove_domain_get.data
    assert b"Failed to remove domains beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu." in response_settings_remove_domain_get.data

def test_settings_enabled_account_remove_domain(client,app):
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

    # Test POST /login with newly registred account and user.
    assert client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login}).status_code == 302

    # Test GET /settings/add_domain
    response_settings_add_domain_get = client.get("/settings/add_domain")
    assert response_settings_add_domain_get.status_code == 200
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_domain_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_domain_get.data
    assert b"Is account enabled: Yes" in response_settings_add_domain_get.data
    assert b"<h3>Add Domain</h3>" in response_settings_add_domain_get.data
    
    # Get csrf_token from /settings/add_domain
    csrf_token_settings_add_domain = get_csrf_token(response_settings_add_domain_get.data)

    # Test to add account domain
    response_settings_add_domain_post = client.post("/settings/add_domain", data={'domain':"test.ddmail.se", 'csrf_token':csrf_token_settings_add_domain})
    assert response_settings_add_domain_post.status_code == 200
    assert b"<h3>Add Domain</h3>" in response_settings_add_domain_post.data
    assert b"Successfully added domain." in response_settings_add_domain_post.data
    
    # Test GET /settings/remove_domain
    response_settings_remove_domain_get = client.get("/settings/remove_domain")
    assert response_settings_remove_domain_get.status_code == 200
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_remove_domain_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_remove_domain_get.data
    assert b"Is account enabled: Yes" in response_settings_remove_domain_get.data
    assert b"<h3>Remove Domain</h3>" in response_settings_remove_domain_get.data
    
    # Get csrf_token from /settings/remove_domain
    csrf_token_settings_remove_domain = get_csrf_token(response_settings_remove_domain_get.data)

    #
    #
    # Test wrong csrf_token on /settings/remove_domain
    assert client.post("/settings/remove_domain", data={'remove_domain':"test.ddmail.se", 'csrf_token':"wrong csrf_token"}).status_code == 400

    #
    #
    # Test empty csrf_token on /settings/remove_domain
    response_settings_remove_domain_empty_csrf_post = client.post("/settings/remove_domain", data={'remove_domain':"test.ddmail.se", 'csrf_token':""})
    assert b"The CSRF token is missing" in response_settings_remove_domain_empty_csrf_post.data
    
    #
    #
    # Test to remove account domain.
    response_settings_remove_domain_post = client.post("/settings/remove_domain", data={'remove_domain':"test.ddmail.se", 'csrf_token':csrf_token_settings_remove_domain})
    assert b"<h3>Remove Domain</h3>" in response_settings_remove_domain_post.data
    assert b"Successfully removed domain" in response_settings_remove_domain_post.data
    
    #
    #
    # Test to remove account domain with illigal char.
    response_settings_remove_domain_post = client.post("/settings/remove_domain", data={'remove_domain':"t..est.ddmail.se", 'csrf_token':csrf_token_settings_remove_domain})
    assert b"<h3>Remove Domain Error</h3>" in response_settings_remove_domain_post.data
    assert b"Failed to remove domain, domain backend validation failed." in response_settings_remove_domain_post.data
    
    #
    #
    # Test to remove account domain with illigal char.
    response_settings_remove_domain_post = client.post("/settings/remove_domain", data={'remove_domain':"te--st.ddmail.se.se", 'csrf_token':csrf_token_settings_remove_domain})
    assert b"<h3>Remove Domain Error</h3>" in response_settings_remove_domain_post.data
    assert b"Failed to remove domain, domain backend validation failed." in response_settings_remove_domain_post.data
    
    #
    #
    # Test to remove account domain with illigal char.
    response_settings_remove_domain_post = client.post("/settings/remove_domain", data={'remove_domain':"t\"est.ddmail.se", 'csrf_token':csrf_token_settings_remove_domain})
    assert b"<h3>Remove Domain Error</h3>" in response_settings_remove_domain_post.data
    assert b"Failed to remove domain, domain backend validation failed." in response_settings_remove_domain_post.data
    
    #
    #
    # Test to remove account domain with illigal char.
    response_settings_remove_domain_post = client.post("/settings/remove_domain", data={'remove_domain':"test.ddm#ail.se", 'csrf_token':csrf_token_settings_remove_domain})
    assert b"<h3>Remove Domain Error</h3>" in response_settings_remove_domain_post.data
    assert b"Failed to remove domain, domain backend validation failed." in response_settings_remove_domain_post.data
    
    #
    #
    # Test to remove account domain with illigal char.
    response_settings_remove_domain_post = client.post("/settings/remove_domain", data={'remove_domain':"test.ddm<ail.se", 'csrf_token':csrf_token_settings_remove_domain})
    assert b"<h3>Remove Domain Error</h3>" in response_settings_remove_domain_post.data
    assert b"Failed to remove domain, domain backend validation failed." in response_settings_remove_domain_post.data
    
    #
    #
    # Test to remove account domain with domain that does not exist.
    response_settings_remove_domain_post = client.post("/settings/remove_domain", data={'remove_domain':"mydomain2.se", 'csrf_token':csrf_token_settings_remove_domain})
    assert b"<h3>Remove Domain Error</h3>" in response_settings_remove_domain_post.data
    assert b"Failed to remove domain, domain does not exist or is not owned by your account." in response_settings_remove_domain_post.data
