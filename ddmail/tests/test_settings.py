import pytest
import re
import datetime
from io import BytesIO
from tests.helpers import get_csrf_token
from tests.helpers import get_register_data

from ddmail.models import db, Account, Email, Domain, Alias, Global_domain, User, Authenticated

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

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()
        db.session.commit()

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

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()
        db.session.commit()

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

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()

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

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()

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

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()
        
        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()

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

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()

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

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()
        
        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()
        
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

    # Test POST /login with newly registred account and user, check that account and username is correct and that account is disabled.
    response_login_post = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login},follow_redirects = True)
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_login_post.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_login_post.data
    assert b"Is account enabled: No" in response_login_post.data

    # Test GET /settings/add_user_to_account.
    assert client.get("/settings/add_user_to_account").status_code == 200
    response_settings_add_user_to_account_get = client.get("/settings/add_user_to_account")
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_settings_add_user_to_account_get.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_settings_add_user_to_account_get.data
    assert b"Is account enabled: No" in response_settings_add_user_to_account_get.data
    assert b"Failed to add user beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu." in response_settings_add_user_to_account_get.data

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()

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

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()

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

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()

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

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()

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

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()

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

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()

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

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()

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

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()

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

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()

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

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()

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

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()

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

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()

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

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()
