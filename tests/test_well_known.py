from flask import session
import pytest


def test_well_known_mta_sts_txt(client):
    """Test MTA-STS policy file accessibility

    This test verifies that the MTA-STS (Mail Transfer Agent Strict Transport
    Security) policy file is accessible at the standard well-known location.
    This file is critical for email security as it defines the security policy
    for mail servers connecting to the domain.
    """
    response = client.get("/.well-known/mta-sts.txt")
    assert response.status_code == 200


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
