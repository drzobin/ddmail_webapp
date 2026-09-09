import argparse
import os
import random
import sys
from datetime import date

import toml
from flask import Flask

from ddmail_webapp.models import Voucher, db
from ddmail_webapp.shared import hash_voucher_code


def generate_voucher_code(length: int = 24) -> str:
    """Generate a random uppercase voucher code excluding 0, O, I, 1.

    Args:
        length: Length of the voucher code to generate (default: 24)

    Returns:
        Random uppercase string of specified length, excluding 0, O, I, 1
    """
    # Uppercase letters excluding O and I, digits excluding 0 and 1
    characters = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    return ''.join(random.choice(characters) for _ in range(length))





def create_app(config_file: str, mode: str) -> Flask:
    """Create a Flask app configured for the specified mode.

    Args:
        config_file: Path to the TOML configuration file
        mode: The mode to use (DEVELOPMENT, TESTING, or PRODUCTION)

    Returns:
        Configured Flask app instance
    """
    # Load the configuration
    with open(config_file, 'r') as f:
        toml_config = toml.load(f)

    if mode not in toml_config:
        print(f"Error: mode '{mode}' not found in config file")
        sys.exit(1)

    # Set MODE environment variable for consistency
    os.environ['MODE'] = mode

    # Create Flask app
    app = Flask(__name__)

    # Configure from the selected mode
    mode_config = toml_config[mode]
    app.config['SQLALCHEMY_DATABASE_URI'] = mode_config['SQLALCHEMY_DATABASE_URI']
    app.config['VOUCHER_SECRET_KEY'] = mode_config['VOUCHER_SECRET_KEY']
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize database
    db.init_app(app)

    return app


def main() -> None:
    """Main entry point for the voucher CLI."""
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description='Add vouchers to the database'
    )
    parser.add_argument(
        '--config',
        required=True,
        help='Path to the TOML configuration file'
    )
    parser.add_argument(
        '--funds',
        type=int,
        required=True,
        help='Amount of funds in SEK each voucher represents'
    )
    parser.add_argument(
        '--length',
        type=int,
        default=24,
        help='Length of the voucher code (default: 24)'
    )
    parser.add_argument(
        '--number',
        type=int,
        default=1,
        help='Number of vouchers to generate (default: 1)'
    )
    parser.add_argument(
        '--mode',
        required=True,
        choices=['DEVELOPMENT', 'TESTING', 'PRODUCTION'],
        help='Configuration mode to use (DEVELOPMENT, TESTING, or PRODUCTION)'
    )

    args: argparse.Namespace = parser.parse_args()

    # Validate funds amount
    if args.funds <= 0:
        print("Error: funds must be a positive integer")
        sys.exit(1)

    # Validate length
    if args.length <= 0:
        print("Error: length must be a positive integer")
        sys.exit(1)

    # Validate number
    if args.number <= 0:
        print("Error: number must be a positive integer")
        sys.exit(1)

    # Create Flask app with the specified configuration
    app = create_app(args.config, args.mode)

    # Get the secret key from the app config
    secret_key: str = app.config['VOUCHER_SECRET_KEY']
    if not secret_key or secret_key == 'change_me':
        print("Error: VOUCHER_SECRET_KEY not properly configured in config file")
        sys.exit(1)

    # Generate and add vouchers
    with app.app_context():
        for _ in range(args.number):
            # Generate cleartext voucher code
            cleartext_code: str = generate_voucher_code(args.length)

            # Hash the voucher code using HMAC-SHA256
            voucher_code_hash: str = hash_voucher_code(cleartext_code, secret_key)

            # Create and save the voucher
            voucher = Voucher(
                voucher_code_hash=voucher_code_hash,
                funds_in_sek=args.funds,
                created=date.today()
            )

            db.session.add(voucher)
            db.session.commit()

            print(cleartext_code)


if __name__ == '__main__':
    main()
