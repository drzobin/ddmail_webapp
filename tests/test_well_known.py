from flask import session
import pytest

def test_well_known_mta_sts_txt(client):
    response = client.get("/.well-known/mta-sts.txt")
    assert response.status_code == 200

def test_security_txt(client):
    response = client.get("/security.txt")
    assert response.status_code == 200

def testwell_known__security_txt(client):
    response = client.get("/.well-known/security.txt")
    assert response.status_code == 200

