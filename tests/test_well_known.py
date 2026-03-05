from flask import session
import pytest


def test_well_known_mta_sts_txt(client, app):
    """Test MTA-STS policy file accessibility and dynamic mx content

    This test verifies that the MTA-STS (Mail Transfer Agent Strict Transport
    Security) policy file is accessible at the standard well-known location.
    This file is critical for email security as it defines the security policy
    for mail servers connecting to the domain. The mx hosts are dynamically
    set from the MTA_STS_MX configuration variable, which is a list of
    hostnames that each produce a separate mx: line.
    """
    response = client.get("/.well-known/mta-sts.txt")
    assert response.status_code == 200
    assert response.content_type == "text/plain; charset=utf-8"
    data = response.data.decode("utf-8")
    assert "version: STSv1" in data
    assert "mode: enforce" in data
    assert "max_age: 604800" in data

    # Verify that each configured mx host has a corresponding mx: line.
    mta_sts_mx_list = app.config["MTA_STS_MX"]
    for mx in mta_sts_mx_list:
        assert f"mx: {mx}" in data


def test_well_known_mta_sts_txt_multiple_mx(app):
    """Test MTA-STS policy file with multiple mx hosts

    This test verifies that when MTA_STS_MX is configured with multiple
    hostnames, the response contains a separate mx: line for each one.
    """
    original_mx = app.config["MTA_STS_MX"]
    app.config["MTA_STS_MX"] = ["mail.ddmail.se", "smtp.ddmail.se"]

    with app.test_client() as client:
        response = client.get("/.well-known/mta-sts.txt")
        assert response.status_code == 200
        data = response.data.decode("utf-8")
        assert "mx: mail.ddmail.se" in data
        assert "mx: smtp.ddmail.se" in data
        assert data.count("mx: ") == 2

    app.config["MTA_STS_MX"] = original_mx


def test_security_txt(client, app):
    """Test security.txt file accessibility and dynamic content at root

    This test verifies that the security.txt file is accessible at the root
    level of the domain and that the response contains the dynamically
    generated fields from the SECURITY_TXT_* configuration variables.
    """
    response = client.get("/security.txt")
    assert response.status_code == 200
    assert response.content_type == "text/plain; charset=utf-8"
    data = response.data.decode("utf-8")

    # Verify that each configured contact has a corresponding Contact: line.
    for contact in app.config["SECURITY_TXT_CONTACT"]:
        assert f"Contact: {contact}" in data

    # Verify Expires field.
    assert f"Expires: {app.config['SECURITY_TXT_EXPIRES']}" in data

    # Verify that each configured encryption URI has an Encryption: line.
    for encryption in app.config["SECURITY_TXT_ENCRYPTION"]:
        assert f"Encryption: {encryption}" in data

    # Verify Preferred-Languages field.
    assert (
        f"Preferred-Languages: {app.config['SECURITY_TXT_PREFERRED_LANGUAGES']}" in data
    )

    # Verify that each configured canonical URI has a Canonical: line.
    for canonical in app.config["SECURITY_TXT_CANONICAL"]:
        assert f"Canonical: {canonical}" in data


def testwell_known__security_txt(client, app):
    """Test security.txt file accessibility and dynamic content at well-known location

    This test verifies that the security.txt file is accessible at the
    standard RFC 9116 well-known location and that the response contains
    the dynamically generated fields from the SECURITY_TXT_* configuration
    variables.
    """
    response = client.get("/.well-known/security.txt")
    assert response.status_code == 200
    assert response.content_type == "text/plain; charset=utf-8"
    data = response.data.decode("utf-8")

    for contact in app.config["SECURITY_TXT_CONTACT"]:
        assert f"Contact: {contact}" in data

    assert f"Expires: {app.config['SECURITY_TXT_EXPIRES']}" in data

    for encryption in app.config["SECURITY_TXT_ENCRYPTION"]:
        assert f"Encryption: {encryption}" in data

    assert (
        f"Preferred-Languages: {app.config['SECURITY_TXT_PREFERRED_LANGUAGES']}" in data
    )

    for canonical in app.config["SECURITY_TXT_CANONICAL"]:
        assert f"Canonical: {canonical}" in data


def test_security_txt_multiple_values(app):
    """Test security.txt with multiple values for list fields

    This test verifies that when SECURITY_TXT_CONTACT, SECURITY_TXT_ENCRYPTION,
    and SECURITY_TXT_CANONICAL are configured with multiple entries, each entry
    produces a separate line in the response.
    """
    original_contact = app.config["SECURITY_TXT_CONTACT"]
    original_encryption = app.config["SECURITY_TXT_ENCRYPTION"]
    original_canonical = app.config["SECURITY_TXT_CANONICAL"]

    app.config["SECURITY_TXT_CONTACT"] = [
        "mailto:security@crew.ddmail.se",
        "mailto:admin@ddmail.se",
    ]
    app.config["SECURITY_TXT_ENCRYPTION"] = [
        "https://www.ddmail.se/static/contact_security_pubkey.asc",
        "https://ddmail.se/static/contact_security_pubkey.asc",
        "https://backup.ddmail.se/static/contact_security_pubkey.asc",
    ]
    app.config["SECURITY_TXT_CANONICAL"] = [
        "https://www.ddmail.se/.well-known/security.txt",
        "https://ddmail.se/.well-known/security.txt",
    ]

    with app.test_client() as client:
        response = client.get("/.well-known/security.txt")
        assert response.status_code == 200
        data = response.data.decode("utf-8")
        assert data.count("Contact: ") == 2
        assert "Contact: mailto:security@crew.ddmail.se" in data
        assert "Contact: mailto:admin@ddmail.se" in data
        assert data.count("Encryption: ") == 3
        assert data.count("Canonical: ") == 2

    app.config["SECURITY_TXT_CONTACT"] = original_contact
    app.config["SECURITY_TXT_ENCRYPTION"] = original_encryption
    app.config["SECURITY_TXT_CANONICAL"] = original_canonical
