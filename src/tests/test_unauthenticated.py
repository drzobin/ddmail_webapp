from flask import session
import pytest

def test_main(client):
    response = client.get("/")
    assert client.get("/").status_code == 200
    assert b"Logged in on account: Not logged in" in response.data
    assert b"Logged in as user: Not logged in" in response.data
    assert b"Main" in response.data
    assert b"Login" in response.data
    assert b"Register" in response.data
    assert b"About" in response.data

def test_about(client):
    response = client.get("/about")
    assert client.get("/about").status_code == 200
    assert b"Logged in on account: Not logged in" in response.data
    assert b"Logged in as user: Not logged in" in response.data
    assert b"Main" in response.data
    assert b"Login" in response.data
    assert b"Register" in response.data
    assert b"About" in response.data
