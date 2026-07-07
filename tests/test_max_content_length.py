"""Tests for the MAX_CONTENT_LENGTH upload size cap.

MAX_CONTENT_LENGTH is a defense-in-depth control that prevents an authenticated
(or unauthenticated) client from exhausting a worker's memory by uploading a
very large request body. The limit is enforced by Werkzeug before any route
handler runs, and the app registers a friendly 413 error handler in
`ddmail_webapp.__init__`.

These tests verify:
  * MAX_CONTENT_LENGTH is loaded from the TOML config into app.config.
  * create_app fails fast when the key is absent from the TOML config.
  * A POST body larger than the limit is rejected with HTTP 413.
  * The friendly `message.html` "Upload too large" page is rendered instead of
    the raw Werkzeug default.
  * A modestly-sized POST body is NOT rejected (guards against the limit being
    accidentally set too small).
  * The OpenPGP public-key upload endpoint (whose vulnerability motivated this
    fix) is covered by the cap, and the 413 fires before auth is reached.
"""

from io import BytesIO

import pytest
import toml

from ddmail_webapp import create_app

# --------------------------------------------------------------------------- #
# Config-loading tests
# --------------------------------------------------------------------------- #


def test_max_content_length_is_configured(app):
    """MAX_CONTENT_LENGTH is loaded from the TOML config into app.config."""
    assert "MAX_CONTENT_LENGTH" in app.config
    assert isinstance(app.config["MAX_CONTENT_LENGTH"], int)
    assert app.config["MAX_CONTENT_LENGTH"] > 0


def test_missing_max_content_length_key_raises(config_file, tmp_path):
    """create_app raises when MAX_CONTENT_LENGTH is absent from the TOML.

    The key is intentionally required (not defaulted) so a mis-templated deploy
    config fails fast at startup rather than silently disabling the cap.
    """
    if config_file is None:
        pytest.skip("--config not supplied to pytest")

    with open(config_file) as f:
        cfg = toml.load(f)

    # Remove MAX_CONTENT_LENGTH from the TESTING section only.
    assert "MAX_CONTENT_LENGTH" in cfg["TESTING"], (
        "Precondition: the config used for tests must contain "
        "MAX_CONTENT_LENGTH in the TESTING section."
    )
    cfg["TESTING"].pop("MAX_CONTENT_LENGTH")

    modified = tmp_path / "no_max_content_length.toml"
    with open(modified, "w") as f:
        toml.dump(cfg, f)

    with pytest.raises(KeyError):
        create_app(config_file=str(modified))


# --------------------------------------------------------------------------- #
# Enforcement tests
# --------------------------------------------------------------------------- #


def test_oversized_post_returns_413(client, app):
    """A POST body larger than MAX_CONTENT_LENGTH is rejected with HTTP 413."""
    limit = app.config["MAX_CONTENT_LENGTH"]
    oversized = b"x" * (limit + 1024)

    response = client.post(
        "/register",
        data=oversized,
        content_type="application/octet-stream",
    )

    assert response.status_code == 413


def test_413_response_uses_friendly_handler(client, app):
    """The custom errorhandler renders `message.html` (not the Werkzeug default).

    This guards the fact that we registered
    `@app.errorhandler(RequestEntityTooLarge)` in create_app().
    """
    limit = app.config["MAX_CONTENT_LENGTH"]
    oversized = b"x" * (limit + 1024)

    response = client.post(
        "/register",
        data=oversized,
        content_type="application/octet-stream",
    )

    assert response.status_code == 413
    assert b"Upload too large" in response.data
    assert b"The uploaded file is larger than the allowed limit." in response.data


def test_reasonable_upload_is_not_413(client, app):
    """A modestly-sized POST body is not rejected by MAX_CONTENT_LENGTH.

    Regression guard against accidentally setting the limit too small (e.g. 0).
    We don't assert the exact success status here because /register requires a
    CSRF token; we only assert that the response is NOT a 413.
    """
    # 4 KiB is smaller than any sane MAX_CONTENT_LENGTH for this app.
    normal = b"x" * 4096
    assert app.config["MAX_CONTENT_LENGTH"] > len(normal), (
        "Precondition: MAX_CONTENT_LENGTH must be larger than 4 KiB for this "
        "regression test to be meaningful."
    )

    response = client.post(
        "/register",
        data=normal,
        content_type="application/octet-stream",
    )

    assert response.status_code != 413


def test_oversized_upload_to_openpgp_endpoint_returns_413(client, app):
    """The OpenPGP public-key upload endpoint is covered by the cap.

    This is the endpoint whose vulnerability (unbounded file.read()) motivated
    adding MAX_CONTENT_LENGTH in the first place. The 413 must fire before the
    route's auth check runs, so we do NOT need to establish a session.
    """
    limit = app.config["MAX_CONTENT_LENGTH"]
    oversized = b"x" * (limit + 1024)

    response = client.post(
        "/settings/upload_openpgp_public_key",
        buffered=True,
        content_type="multipart/form-data",
        data={
            "openpgp_public_key": (BytesIO(oversized), "big.asc"),
        },
    )

    assert response.status_code == 413
