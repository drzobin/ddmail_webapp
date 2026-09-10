import argparse
import os
import sys
from datetime import date

import toml
from flask import Flask

from ddmail_webapp.models import Account, Receipt, db
from ddmail_webapp.auth import generate_token


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
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize database
    db.init_app(app)

    return app


def main() -> None:
    """Main entry point for the add_funds CLI."""
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description='Add funds to an account'
    )
    parser.add_argument(
        '--config',
        required=True,
        help='Path to the TOML configuration file'
    )
    parser.add_argument(
        '--payment-token',
        required=True,
        help='Payment token of the account to add funds to'
    )
    parser.add_argument(
        '--amount',
        type=int,
        required=True,
        help='Amount of funds in SEK to add to the account'
    )
    parser.add_argument(
        '--mode',
        required=True,
        choices=['DEVELOPMENT', 'TESTING', 'PRODUCTION'],
        help='Configuration mode to use (DEVELOPMENT, TESTING, or PRODUCTION)'
    )

    args: argparse.Namespace = parser.parse_args()

    # Validate amount
    if args.amount <= 0:
        print("Error: amount must be a positive integer")
        sys.exit(1)

    # Create Flask app with the specified configuration
    app = create_app(args.config, args.mode)

    # Add funds to the account
    with app.app_context():
        # Find the account by payment token
        account = Account.query.filter_by(payment_token=args.payment_token).first()

        if account is None:
            print(f"Error: No account found with payment token '{args.payment_token}'")
            sys.exit(1)

        print(f"Account {account.account} current funds {account.funds_in_sek} SEK")

        # If accounts is not enabled then enable it.
        if not account.is_enabled:
            account.is_enabled = True

        # Add funds to the account and generate new payment token.
        account.funds_in_sek =  account.funds_in_sek + args.amount
        account.payment_token = generate_token(24)
        db.session.commit()

        # Create receipt.
        new_receipt = Receipt(
            payment_token=args.payment_token,
            funds_in_sek=args.amount,
            created=date.today(),
        )
        db.session.add(new_receipt)
        db.session.commit()

        print(f"Added {args.amount} SEK to account {account.account} with payment token {args.payment_token}")
        print(f"Account {account.account} new funds {account.funds_in_sek} SEK")


if __name__ == '__main__':
    main()
