from flask import current_app
from ddmail_webapp.validators import is_email_allowed, is_domain_allowed, is_password_allowed
import pytest
import os

def test_is_password_allowed():
    assert is_password_allowed("a2A83") == True
    assert is_password_allowed("1a2A835") == True
    assert is_password_allowed("F1a2A835V") == True
    assert is_password_allowed("as3dgD5khjFgsad6Gjgb6") == True
    assert is_password_allowed("aA8/+=\\") == False
    assert is_password_allowed("aA8/+=\\vfgg") == False
    assert is_password_allowed("aAx\"fds") == False
    assert is_password_allowed("a-b3") == False
    assert is_password_allowed("a--b3") == False
    assert is_password_allowed("a<b3") == False
    assert is_password_allowed("a>b5") == False
    assert is_password_allowed("a>>6") == False
    assert is_password_allowed("as3dgD5khjFgsad6Gj_gb6") == False
    assert is_password_allowed("as3dgD5khjF#gsad6Gjgb6") == False
    assert is_password_allowed("as3dgD5<khjFgsad6Gjgb6") == False
    assert is_password_allowed("as3dgD5>khjFgsad6Gjgb6") == False
    assert is_password_allowed("as3dgD5-khjFgsad6Gjgb6") == False
    assert is_password_allowed("as3dgD5--khjFgsad6Gjgb6") == False
    assert is_password_allowed("as3dgD5@khjFgsad6Gjgb6") == False
    assert is_password_allowed("as3dgD5|khjFgsad6Gjgb6") == False
    assert is_password_allowed("as3dg;D5khjFgsad6Gjgb6") == False

def test_is_email_allowed():
    assert is_email_allowed("test@test.se") == True
    assert is_email_allowed("test@tes-t.se") == True
    assert is_email_allowed("test@tes_t.se") == False
    assert is_email_allowed("t@t.s") == False
    assert is_email_allowed("test@test.se.") == False
    assert is_email_allowed(".test@test.se") == False
    assert is_email_allowed("@test.se") == False
    assert is_email_allowed("test.test.se@") == False
    assert is_email_allowed("test@te<>st.se") == False
    assert is_email_allowed("te>st@test.se") == False
    assert is_email_allowed("te<st@test.se") == False
    assert is_email_allowed("te=st@test.se") == False
    assert is_email_allowed("test@tes=t.se") == False
    assert is_email_allowed("test@test..se") == False
    assert is_email_allowed("t\"est@test.se") == False

def test_is_domain_allowed():
    assert is_domain_allowed("test.se") == True
    assert is_domain_allowed("testtes-t.se") == True
    assert is_domain_allowed("t.s") == False
    assert is_domain_allowed("test.se.") == False
    assert is_domain_allowed("te_st.se") == False
    assert is_domain_allowed(".test@test.se") == False
    assert is_domain_allowed("t@est.se") == False
    assert is_domain_allowed("test.test.se@") == False
    assert is_domain_allowed("testte<>st.se") == False
    assert is_domain_allowed("te>sttest.se") == False
    assert is_domain_allowed("te<test.se") == False
    assert is_domain_allowed("te=sttest.se") == False
    assert is_domain_allowed("test=t.se") == False
    assert is_domain_allowed("testtest..se") == False
    assert is_domain_allowed("t\"est@test.se") == False
