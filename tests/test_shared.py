import string
import pytest
from ddmail_webapp.shared import hash_voucher_code, generate_domain_verification_code


def test_hash_voucher_code_basic():
    """Test basic voucher code hashing functionality

    This test verifies that the hash_voucher_code function produces a valid
    HMAC-SHA256 hex digest when given a cleartext code and secret key.
    """
    cleartext_code = "ABC123"
    secret_key = "my_secret_key"
    
    result = hash_voucher_code(cleartext_code, secret_key)
    
    # Verify the result is a valid hex string
    assert isinstance(result, str)
    assert len(result) == 64  # SHA-256 produces 64-character hex digest
    
    # Verify all characters are hex digits
    assert all(c in string.hexdigits.lower() for c in result)


def test_hash_voucher_code_consistency():
    """Test that hashing the same inputs produces consistent results

    This test verifies that the hash_voucher_code function is deterministic
    and produces the same output for the same inputs.
    """
    cleartext_code = "TEST_CODE"
    secret_key = "TEST_KEY"
    
    result1 = hash_voucher_code(cleartext_code, secret_key)
    result2 = hash_voucher_code(cleartext_code, secret_key)
    
    assert result1 == result2


def test_hash_voucher_code_different_inputs():
    """Test that different inputs produce different hashes

    This test verifies that changing either the cleartext code or the secret
    key produces different hash results.
    """
    cleartext_code1 = "CODE1"
    cleartext_code2 = "CODE2"
    secret_key = "SECRET"
    
    hash1 = hash_voucher_code(cleartext_code1, secret_key)
    hash2 = hash_voucher_code(cleartext_code2, secret_key)
    
    assert hash1 != hash2
    
    # Also test with different secret keys
    secret_key1 = "SECRET1"
    secret_key2 = "SECRET2"
    
    hash3 = hash_voucher_code(cleartext_code1, secret_key1)
    hash4 = hash_voucher_code(cleartext_code1, secret_key2)
    
    assert hash3 != hash4


def test_hash_voucher_code_empty_strings():
    """Test hashing with empty strings

    This test verifies that the hash_voucher_code function handles empty
    strings correctly for both cleartext_code and secret_key parameters.
    """
    # Empty cleartext code
    result1 = hash_voucher_code("", "secret")
    assert isinstance(result1, str)
    assert len(result1) == 64
    
    # Empty secret key
    result2 = hash_voucher_code("code", "")
    assert isinstance(result2, str)
    assert len(result2) == 64
    
    # Both empty
    result3 = hash_voucher_code("", "")
    assert isinstance(result3, str)
    assert len(result3) == 64


def test_hash_voucher_code_unicode():
    """Test hashing with unicode characters

    This test verifies that the hash_voucher_code function correctly handles
    unicode characters in both the cleartext code and secret key.
    """
    cleartext_code = "café123"
    secret_key = "密码key"
    
    result = hash_voucher_code(cleartext_code, secret_key)
    
    assert isinstance(result, str)
    assert len(result) == 64
    assert all(c in string.hexdigits.lower() for c in result)


def test_generate_domain_verification_code_basic():
    """Test basic domain verification code generation

    This test verifies that the generate_domain_verification_code function
    produces a token that meets all security requirements.
    """
    length = 20
    token = generate_domain_verification_code(length)
    
    # Verify the token has the correct length
    assert len(token) == length
    
    # Verify the token contains only lowercase letters and digits
    valid_chars = string.ascii_lowercase + string.digits
    assert all(c in valid_chars for c in token)
    
    # Verify the token contains at least one lowercase letter
    assert any(c.islower() for c in token)
    
    # Verify the token contains at least 4 digits
    assert sum(c.isdigit() for c in token) >= 4


def test_generate_domain_verification_code_length_variations():
    """Test domain verification code generation with various lengths

    This test verifies that the generate_domain_verification_code function
    works correctly with different length parameters.
    """
    for length in [10, 15, 20, 30, 50]:
        token = generate_domain_verification_code(length)
        assert len(token) == length
        
        valid_chars = string.ascii_lowercase + string.digits
        assert all(c in valid_chars for c in token)
        assert any(c.islower() for c in token)
        assert sum(c.isdigit() for c in token) >= 4


def test_generate_domain_verification_code_minimum_length():
    """Test domain verification code generation with minimum viable length

    This test verifies that the generate_domain_verification_code function
    can generate tokens even with the minimum length that satisfies the
    security requirements (at least 4 digits + at least 1 letter = 5).
    """
    # Minimum length to satisfy requirements: 4 digits + 1 letter = 5
    length = 5
    token = generate_domain_verification_code(length)
    
    assert len(token) == length
    assert any(c.islower() for c in token)
    assert sum(c.isdigit() for c in token) >= 4


def test_generate_domain_verification_code_uniqueness():
    """Test that generated tokens are unique

    This test verifies that multiple calls to generate_domain_verification_code
    produce different tokens (with very high probability).
    """
    length = 20
    token1 = generate_domain_verification_code(length)
    token2 = generate_domain_verification_code(length)
    
    # While there's a tiny chance of collision, it's astronomically unlikely
    assert token1 != token2


def test_generate_domain_verification_code_always_meets_requirements():
    """Test that many generated tokens all meet security requirements

    This test verifies that the generate_domain_verification_code function
    consistently produces tokens that meet all security requirements.
    """
    length = 15
    num_tests = 100
    
    for _ in range(num_tests):
        token = generate_domain_verification_code(length)
        
        # Check length
        assert len(token) == length
        
        # Check character set
        valid_chars = string.ascii_lowercase + string.digits
        assert all(c in valid_chars for c in token)
        
        # Check lowercase requirement
        assert any(c.islower() for c in token)
        
        # Check digit requirement
        assert sum(c.isdigit() for c in token) >= 4


def test_generate_domain_verification_code_no_uppercase():
    """Test that generated tokens contain no uppercase letters

    This test verifies that the generate_domain_verification_code function
    only produces tokens with lowercase letters and digits, no uppercase.
    """
    length = 20
    num_tests = 50
    
    for _ in range(num_tests):
        token = generate_domain_verification_code(length)
        assert token.islower() or token.isdigit() or (any(c.islower() for c in token) and any(c.isdigit() for c in token))
        # More directly: no uppercase letters
        assert not any(c.isupper() for c in token)
