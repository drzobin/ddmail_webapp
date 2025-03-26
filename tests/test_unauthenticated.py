from flask import session
import pytest

def test_main(client):
    with client.session_transaction() as session:
        session["secret"] = "aBcDeFgH123"

    response = client.get("/")
    assert response.status_code == 200
    assert b"Logged in on account: Not logged in" in response.data
    assert b"Logged in as user: Not logged in" in response.data
    assert b"Main" in response.data
    assert b"Login" in response.data
    assert b"Register" in response.data
    assert b"Pricing and payment" in response.data
    assert b"Terms" in response.data
    assert b"Help" in response.data
    assert b"About" in response.data
    assert b"Contact" in response.data
    assert b"<h2>Main</h2>" in response.data

def test_main_no_session(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Logged in on account: Not logged in" in response.data
    assert b"Logged in as user: Not logged in" in response.data
    assert b"Main" in response.data
    assert b"Login" in response.data
    assert b"Register" in response.data
    assert b"Pricing and payment" in response.data
    assert b"Terms" in response.data
    assert b"Help" in response.data
    assert b"About" in response.data
    assert b"Contact" in response.data
    assert b"<h2>Main</h2>" in response.data

def test_pricing_and_payment(client):
    with client.session_transaction() as session:
        session["secret"] = "aBcDeFgH123"

    response = client.get("/pricing_and_payment")
    assert response.status_code == 200
    assert b"Logged in on account: Not logged in" in response.data
    assert b"Logged in as user: Not logged in" in response.data
    assert b"Main" in response.data
    assert b"Login" in response.data
    assert b"Register" in response.data
    assert b"Pricing and payment" in response.data
    assert b"Terms" in response.data
    assert b"Help" in response.data
    assert b"About" in response.data
    assert b"Contact" in response.data
    assert b"<h2>Pricing and payment</h2>" in response.data

def test_pricing_and_payment_no_session(client):
    response = client.get("/pricing_and_payment")
    assert response.status_code == 200
    assert b"Logged in on account: Not logged in" in response.data
    assert b"Logged in as user: Not logged in" in response.data
    assert b"Main" in response.data
    assert b"Login" in response.data
    assert b"Register" in response.data
    assert b"Pricing and payment" in response.data
    assert b"Terms" in response.data
    assert b"Help" in response.data
    assert b"About" in response.data
    assert b"Contact" in response.data
    assert b"<h2>Pricing and payment</h2>" in response.data

def test_terms(client):
    with client.session_transaction() as session:
        session["secret"] = "aBcDeFgH123"

    response = client.get("/terms")
    assert response.status_code == 200
    assert b"Logged in on account: Not logged in" in response.data
    assert b"Logged in as user: Not logged in" in response.data
    assert b"Main" in response.data
    assert b"Login" in response.data
    assert b"Register" in response.data
    assert b"Pricing and payment" in response.data
    assert b"Terms" in response.data
    assert b"Help" in response.data
    assert b"About" in response.data
    assert b"Contact" in response.data
    assert b"<h2>Terms</h2>" in response.data

def test_terms_no_session(client):
    response = client.get("/terms")
    assert response.status_code == 200
    assert b"Logged in on account: Not logged in" in response.data
    assert b"Logged in as user: Not logged in" in response.data
    assert b"Main" in response.data
    assert b"Login" in response.data
    assert b"Register" in response.data
    assert b"Pricing and payment" in response.data
    assert b"Terms" in response.data
    assert b"Help" in response.data
    assert b"About" in response.data
    assert b"Contact" in response.data
    assert b"<h2>Terms</h2>" in response.data

def test_help(client):
    with client.session_transaction() as session:
        session["secret"] = "aBcDeFgH123"

    response = client.get("/help")
    assert response.status_code == 200
    assert b"Logged in on account: Not logged in" in response.data
    assert b"Logged in as user: Not logged in" in response.data
    assert b"Main" in response.data
    assert b"Login" in response.data
    assert b"Register" in response.data
    assert b"Pricing and payment" in response.data
    assert b"Terms" in response.data
    assert b"Help" in response.data
    assert b"About" in response.data
    assert b"Contact" in response.data
    assert b"<h2>Help</h2>" in response.data

def test_help_no_session(client):
    response = client.get("/help")
    assert response.status_code == 200
    assert b"Logged in on account: Not logged in" in response.data
    assert b"Logged in as user: Not logged in" in response.data
    assert b"Main" in response.data
    assert b"Login" in response.data
    assert b"Register" in response.data
    assert b"Pricing and payment" in response.data
    assert b"Terms" in response.data
    assert b"Help" in response.data
    assert b"About" in response.data
    assert b"Contact" in response.data
    assert b"<h2>Help</h2>" in response.data

def test_about(client):
    with client.session_transaction() as session:
        session["secret"] = "aBcDeFgH123"

    response = client.get("/about")
    assert response.status_code == 200
    assert b"Logged in on account: Not logged in" in response.data
    assert b"Logged in as user: Not logged in" in response.data
    assert b"Main" in response.data
    assert b"Login" in response.data
    assert b"Register" in response.data
    assert b"Pricing and payment" in response.data
    assert b"Terms" in response.data
    assert b"Help" in response.data
    assert b"About" in response.data
    assert b"Contact" in response.data
    assert b"<h2>About</h2>" in response.data

def test_about_no_session(client):
    response = client.get("/about")
    assert response.status_code == 200
    assert b"Logged in on account: Not logged in" in response.data
    assert b"Logged in as user: Not logged in" in response.data
    assert b"Main" in response.data
    assert b"Login" in response.data
    assert b"Register" in response.data
    assert b"Pricing and payment" in response.data
    assert b"Terms" in response.data
    assert b"Help" in response.data
    assert b"About" in response.data
    assert b"Contact" in response.data
    assert b"<h2>About</h2>" in response.data

def test_contact(client):
    with client.session_transaction() as session:
        session["secret"] = "aBcDeFgH123"

    response = client.get("/contact")
    assert response.status_code == 200
    assert b"Logged in on account: Not logged in" in response.data
    assert b"Logged in as user: Not logged in" in response.data
    assert b"Main" in response.data
    assert b"Login" in response.data
    assert b"Register" in response.data
    assert b"Pricing and payment" in response.data
    assert b"Terms" in response.data
    assert b"Help" in response.data
    assert b"About" in response.data
    assert b"Contact" in response.data
    assert b"<h2>Contact</h2>" in response.data

def test_contact_no_session(client):
    response = client.get("/contact")
    assert response.status_code == 200
    assert b"Logged in on account: Not logged in" in response.data
    assert b"Logged in as user: Not logged in" in response.data
    assert b"Main" in response.data
    assert b"Login" in response.data
    assert b"Register" in response.data
    assert b"Pricing and payment" in response.data
    assert b"Terms" in response.data
    assert b"Help" in response.data
    assert b"About" in response.data
    assert b"Contact" in response.data
    assert b"<h2>Contact</h2>" in response.data

def test_ronots(client):
    response = client.get("/robots.txt")
    assert response.status_code == 200

def test_sitemap(client):
    response = client.get("/sitemap.xml")
    assert response.status_code == 200
