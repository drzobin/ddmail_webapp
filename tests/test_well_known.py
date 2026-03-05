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


def test_security_txt(client):
    """Test security.txt file accessibility at root

    This test verifies that the security.txt file is accessible at the root
    level of the domain. This file provides security contact information
    and vulnerability disclosure procedures for security researchers and
    automated security tools.
    """
    response = client.get("/security.txt")
    assert response.status_code == 200


def testwell_known__security_txt(client):
    """Test security.txt file accessibility at well-known location

    This test verifies that the security.txt file is accessible at the
    standard RFC 9116 well-known location. This ensures compliance with
    security disclosure standards and provides a standardized way for
    security researchers to find contact information.
    """
    response = client.get("/.well-known/security.txt")
    assert response.status_code == 200
