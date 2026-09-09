import hashlib
import hmac

def hash_voucher_code(cleartext_code: str, secret_key: str) -> str:
    """Hash the voucher code using HMAC-SHA256.

    Args:
        cleartext_code: The voucher code to hash
        secret_key: The secret key for HMAC hashing

    Returns:
        HMAC-SHA256 hex digest of the voucher code
    """
    return hmac.new(
        secret_key.encode('utf-8'),
        cleartext_code.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
