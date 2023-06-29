import pytest
import re
import datetime
from io import BytesIO
from tests.helpers import get_csrf_token
from tests.helpers import get_register_data

from ddmail.models import db, Account, Email, Domain, Alias, Global_domain, User, Authenticated

def add_testdata_to_db(app):
    with app.app_context():
        # Add account_test01 that is not enabled
        new_account_test01 = Account(account="account_test01", payment_token="111111111111" ,assets_in_sek=0,is_enabled=False, is_gratis=False, created=datetime.datetime.now())
        db.session.add(new_account_test01)
        db.session.commit()

        # Add account account_test02 that is enabled and gratis
        new_account_test02 = Account(account="account_test02", payment_token="222222222222" ,assets_in_sek=0,is_enabled=True, is_gratis=True, created=datetime.datetime.now())
        db.session.add(new_account_test02)
        db.session.commit()

        # Add account account_test03 that is enabled and gratis
        new_account_test03 = Account(account="account_test03", payment_token="333333333333" ,assets_in_sek=0,is_enabled=True, is_gratis=True, created=datetime.datetime.now())
        db.session.add(new_account_test03)
        db.session.commit()

def remove_testdata_from_db(app):
    with app.app_context():
        # Remove account account_test01
        db.session.query(Account).filter(Account.account == "account_test01").delete()
        db.session.commit()

        # Remove account account_test02
        db.session.query(Account).filter(Account.account == "account_test01").delete()
        db.session.commit()

        # Remove account account_test03
        db.session.query(Account).filter(Account.account == "account_test03").delete()
        db.session.commit()

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

    # Test POST /login with newly registred account and user, check that account and username is correct and that account is disabled.
    response_login_post = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login},follow_redirects = True)
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_login_post.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_login_post.data
    assert b"Is account enabled: No" in response_login_post.data

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

    # Test POST /login with newly registred account and user, check that account and username is correct and that account is disabled.
    response_login_post = client.post("/login", buffered=True, content_type='multipart/form-data', data={'user':register_data["username"], 'password':register_data["password"], 'key':(BytesIO(bytes(register_data["key"], 'utf-8')), 'data.key') ,'csrf_token':csrf_token_login},follow_redirects = True)
    assert b"Logged in on account: " + bytes(register_data["account"], 'utf-8') in response_login_post.data
    assert b"Logged in as user: " + bytes(register_data["username"], 'utf-8') in response_login_post.data
    assert b"Is account enabled: No" in response_login_post.data

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

    # Test GET /settings/add_domain.
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
    assert b"Failed to remove domain beacuse this account is disabled." in response_settings_remove_domain_get.data

    # Remove authenticated, user and account that was used in testcase.
    with app.app_context():
        user_from_db = db.session.query(User).filter(User.user == register_data["username"]).first()
        db.session.query(Authenticated).filter(Authenticated.user_id == user_from_db.id).delete()
        db.session.commit()

        db.session.query(User).filter(User.user == register_data["username"]).delete()
        db.session.commit()

        db.session.query(Account).filter(Account.account == register_data["account"]).delete()
