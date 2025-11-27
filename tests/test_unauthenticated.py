from flask import session
import pytest


def test_main(client):
    """Test main page rendering with session

    This test verifies that the main page loads correctly when a user has
    a session established. It checks for proper status code, navigation
    elements, and the main page header while ensuring the user appears
    as not logged in.
    """
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
    """Test main page rendering without session

    This test verifies that the main page loads correctly for visitors
    without any session data. It ensures all navigation elements are present
    and the page displays properly for anonymous users accessing the
    application for the first time.
    """
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
    """Test pricing and payment page with session

    This test verifies that the pricing and payment page renders correctly
    for users with an active session. It checks that all navigation elements
    are present and the specific pricing page header is displayed while
    maintaining unauthenticated user status.
    """
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
    """Test pricing and payment page without session

    This test verifies that the pricing and payment page is accessible
    to anonymous users without any session data. It ensures that potential
    customers can view pricing information and payment options before
    creating an account or logging in.
    """
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
    """Test terms of service page with session

    This test verifies that the terms of service page loads correctly
    for users with an active session. It ensures that users can access
    legal documentation and terms of service while maintaining proper
    navigation and user status display.
    """
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
    """Test terms of service page without session

    This test verifies that the terms of service page is accessible
    to anonymous visitors without requiring a session. This is important
    for legal compliance as users should be able to review terms
    before registering or using the service.
    """
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
    """Test help page rendering with session

    This test verifies that the help page loads correctly for users
    with an active session. It ensures that users can access support
    documentation and help resources while maintaining proper navigation
    structure and user status indication.
    """
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
    """Test help page rendering without session

    This test verifies that the help page is accessible to anonymous
    users without requiring a session. This ensures that potential
    users can access support documentation and troubleshooting
    information before creating an account.
    """
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
    """Test about page rendering with session

    This test verifies that the about page loads correctly for users
    with an active session. It ensures that company information and
    background details are accessible while maintaining proper navigation
    and user authentication status display.
    """
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
    """Test about page rendering without session

    This test verifies that the about page is accessible to anonymous
    visitors without requiring authentication. This allows potential
    users to learn about the company and service before deciding
    to register or engage with the application.
    """
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
    """Test contact page rendering with session

    This test verifies that the contact page loads correctly for users
    with an active session. It ensures that users can access contact
    information and communication channels while maintaining proper
    navigation structure and authentication status.
    """
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
    """Test contact page rendering without session

    This test verifies that the contact page is accessible to anonymous
    users without requiring a session. This is essential for customer
    support as users need to be able to reach out for help or inquiries
    before creating an account.
    """
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
    """Test robots.txt file accessibility

    This test verifies that the robots.txt file is accessible and returns
    a successful response. The robots.txt file is important for SEO and
    web crawler management, providing instructions to search engine bots
    about which parts of the site to crawl.
    """
    response = client.get("/robots.txt")
    assert response.status_code == 200


def test_sitemap(client):
    """Test sitemap.xml file accessibility

    This test verifies that the sitemap.xml file is accessible and returns
    a successful response. The sitemap helps search engines understand
    the structure of the website and discover all available pages for
    improved search engine optimization.
    """
    response = client.get("/sitemap.xml")
    assert response.status_code == 200
