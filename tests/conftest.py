import os
import tempfile
import pytest
from ddmail_webapp import create_app
from ddmail_webapp.models import db, Account, Email, Account_domain, Alias, Global_domain, User, Authenticated

# Set mode to TESTING so we are sure not to run with production configuration running tests.
os.environ["MODE"] = "TESTING"
config_file = None

def pytest_addoption(parser):
    parser.addoption(
        "--config",
        action="store",
        default=None,
        help="Authentication password to use during test.",
    )


@pytest.fixture(scope="session")
def config_file(request):
    """Fixture to retrieve config file"""
    return request.config.getoption("--config")


@pytest.hookimpl(tryfirst=True)
def pytest_sessionstart(session):
    config_file = session.config.getoption("--config")


@pytest.fixture
def app(config_file):
    """Create and configure a new app instance for each test."""
    # Create the app with test config
    app = create_app(config_file = config_file)
    app.config.update({"TESTING": True,})

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
