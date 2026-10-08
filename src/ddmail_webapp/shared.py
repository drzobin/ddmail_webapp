import hashlib
import hmac
import secrets
import string

from fpdf import FPDF
from datetime import date

from ddmail_webapp.models import (
    Receipt,
    db,
)


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


def generate_receipt(payment_token: str):
    """
    Generate a PDF receipt for a payment token.

    This function looks up the receipt belonging to the given payment_token in
    the receipts table and generates a PDF receipt from it. The PDF is built
    entirely in memory with fpdf2 - nothing is written to disc.

    Requires an active Flask application context since it queries the database.

    Args:
        payment_token (str): The payment token the receipt belongs to

    Returns:
        bytes: The receipt as a PDF document in memory, or None if no receipt
        exists for the payment_token

    Raises:
        Nothing - a missing receipt is signaled by returning None
    """
    # Get the receipt from the db and check that it exist.
    receipt = (
        db.session.query(Receipt).filter(Receipt.payment_token == payment_token).first()
    )
    if not receipt:
        return None

    # Build the PDF in memory.
    pdf = FPDF()
    pdf.add_page()

    # Receipt headline.
    pdf.set_font("helvetica", style="B", size=22)
    pdf.cell(0, 10, text="DDMail receipt", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)

    # Receipt number
    pdf.set_font("helvetica", style="B", size=12)
    pdf.cell(0, 8, text="Receipt number: " + receipt.payment_token, new_x="LMARGIN", new_y="NEXT")

    # Dates
    pdf.set_font("helvetica", size=12)
    pdf.cell(0, 8, text="Date funds was added to account: " + receipt.created.strftime("%Y-%m-%d"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", size=12)
    pdf.cell(0, 8, text="Date receipt was created: " + str(date.today()), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", size=12)
    pdf.cell(0, 8, text="Date payment was received: " + str(receipt.payment_received), new_x="LMARGIN", new_y="NEXT")

    # Payment token.
    pdf.set_font("helvetica", size=12)
    pdf.cell(0, 8, text="Payment token: " + receipt.payment_token, new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)

    # Counterpart
    pdf.set_font("helvetica", size=12)
    pdf.cell(0, 8, text="This receipt refers to payment for DDMail e-mail service (www.ddmail.se). DDMail is provided by the ", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, text="company Kodord AB which is also the payment recipients. Kodord AB has organisation number", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, text="559010-5283.", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)
    pdf.ln(4)
    pdf.ln(4)

    # Amount paid.
    pdf.set_font("helvetica", style="B", size=12)
    pdf.cell(0, 8, text="Total amount paid: " + str(receipt.funds_in_sek) + " SEK", new_x="LMARGIN", new_y="NEXT")

    # VAT swedish moms.
    pdf.set_font("helvetica", size=12)
    pdf.cell(0, 8, text="Total amount includes 25% VAT (Moms in Swedish)", new_x="LMARGIN", new_y="NEXT")

    # Return the PDF as bytes.
    return bytes(pdf.output())
