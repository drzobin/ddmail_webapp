import os
import tempfile

import pytest

from ddmail import create_app
from ddmail.models import db, Account, Email, Account_domain, Alias, Global_domain, User, Authenticated

@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    # Create the app with common test config
    app = create_app({"TESTING": True})

    # Empty db
    with app.app_context():
        db.session.query(Authenticated).delete()
        db.session.query(User).delete()
        db.session.query(Alias).delete()
        db.session.query(Email).delete()
        db.session.query(Account_domain).delete()
        db.session.query(Global_domain).delete()
        db.session.query(Account).delete()
        db.session.commit()

    yield app

@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()

@pytest.fixture
def runner(app):
    """A test runner for the app's Click commands."""
    return app.test_cli_runner()
