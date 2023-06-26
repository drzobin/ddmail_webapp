import pytest
import re
from io import BytesIO
from tests.helpers import get_csrf_token
from tests.helpers import get_register_data

def test_settings_disabled_account(client):
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

def test_settings_disabled_account_payment_token(client):
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

def test_settings_disabled_account_add_domain(client):
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
