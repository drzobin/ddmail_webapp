import hashlib
import hmac
import secrets
import string

def hash_voucher_code(cleartext_code: str, secret_key: str) -> str:
    """Hash the voucher code using HMAC-SHA256.

    Args:
        cleartext_code: The voucher code to hash
        secret_key: The secret key for HMAC hashing

    Returns:
        HMAC-SHA256 hex digest of the voucher code

    Parameters:
        cleartext_code (str): The voucher code to hash
        secret_key (str): The secret key for HMAC hashing
    """
    return hmac.new(
        secret_key.encode('utf-8'),
        cleartext_code.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

def generate_domain_verification_code(length):
    """
    Generate a secure token for domain verification.

    This function creates a cryptographically secure token using lowercase
    letters and digits. The token ensures minimum security requirements with
    at least 4 digits.

    Returns:
        str: A secure token containing lowercase letters and digits

    Parameters:
        length (int): The desired length of the generated token

    Security Requirements:
        Must contain at least one lowercase letter
        Must contain at least 4 digits
        Uses cryptographically secure random generation
        Character set: a-z, 0-9
    """
    alphabet = string.ascii_lowercase + string.digits
    while True:
        token = "".join(secrets.choice(alphabet) for i in range(length))
        if any(c.islower() for c in token) and sum(c.isdigit() for c in token) >= 4:
            break
    return token
