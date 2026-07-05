import logging
import logging.handlers
import os
import sys
from logging import FileHandler
from logging.config import dictConfig

import toml
from flask import Flask, render_template
from flask_wtf.csrf import CSRFProtect
from werkzeug.exceptions import RequestEntityTooLarge


def create_app(config_file=None, test_config=None):
    """Create and configure an instance of the Flask application for ddmail webapp.

    This function initializes the Flask application with appropriate configuration
    settings loaded from a TOML file. It sets up logging, loads environment-specific
    configurations, and registers blueprints.

    Args:
        config_file (str, optional): Path to the TOML configuration file. Required.
        test_config (dict, optional): Test configuration to override the loaded config.
                                      Not currently used but available for testing.

    Returns:
        Flask: Configured Flask application instance

    Raises:
        SystemExit: If config_file is not provided, MODE environment variable is invalid,
                   or if LOGLEVEL is not properly configured.

    Note:
        The application relies on the MODE environment variable to determine which
        configuration section to load (PRODUCTION, TESTING, or DEVELOPMENT).
        Each mode requires specific configuration parameters in the TOML file.
    """
    # Configure logging.
    log_format = "[%(asctime)s] ddmail_webapp %(levelname)s in %(module)s %(funcName)s %(lineno)s: %(message)s"
    dictConfig(
        {
            "version": 1,
            "formatters": {"default": {"format": log_format}},
            "handlers": {
                "wsgi": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://flask.logging.wsgi_errors_stream",
                    "formatter": "default",
                },
            },
            "root": {"level": "INFO", "handlers": ["wsgi"]},
        }
    )

    app = Flask(__name__, instance_relative_config=True)

    toml_config = None

    # Check if config_file has been set.
    if config_file is None:
        print("Error: you need to set path to configuration file in toml format")
        sys.exit(1)

    # Parse toml config file.
    with open(config_file, "r") as f:
        toml_config = toml.load(f)

    # Set app configurations from toml config file.
    mode = os.environ.get("MODE")
    print("Running in MODE: " + str(mode))

    # Apply configuration for the specific MODE.
    if mode == "PRODUCTION" or mode == "TESTING" or mode == "DEVELOPMENT":
        app.config["SECRET_KEY"] = toml_config[mode]["SECRET_KEY"]
        app.config["SQLALCHEMY_DATABASE_URI"] = toml_config[mode][
            "SQLALCHEMY_DATABASE_URI"
        ]
        app.config["WTF_CSRF_SECRET_KEY"] = toml_config[mode]["WTF_CSRF_SECRET_KEY"]

        # Cap request body size.
        app.config["MAX_CONTENT_LENGTH"] = toml_config[mode]["MAX_CONTENT_LENGTH"]

        # Configure services that ddmail_webapp depend on.
        app.config["EMAIL_REMOVER_URL"] = toml_config[mode]["EMAIL_REMOVER_URL"]
        app.config["EMAIL_REMOVER_PASSWORD"] = toml_config[mode][
            "EMAIL_REMOVER_PASSWORD"
        ]
        app.config["DMCP_KEYHANDLER_URL"] = toml_config[mode]["DMCP_KEYHANDLER_URL"]
        app.config["DMCP_KEYHANDLER_PASSWORD"] = toml_config[mode][
            "DMCP_KEYHANDLER_PASSWORD"
        ]
        app.config["OPENPGP_KEYHANDLER_URL"] = toml_config[mode][
            "OPENPGP_KEYHANDLER_URL"
        ]
        app.config["OPENPGP_KEYHANDLER_PASSWORD"] = toml_config[mode][
            "OPENPGP_KEYHANDLER_PASSWORD"
        ]

        # Configure payment information.
        app.config["PAYMENT_BANKGIRO"] = toml_config[mode]["PAYMENT_BANKGIRO"]

        # Configure dns record checked when adding account/own domains.
        app.config["MX_RECORD_HOST"] = toml_config[mode]["MX_RECORD_HOST"]
        app.config["MX_RECORD_PRIORITY"] = toml_config[mode]["MX_RECORD_PRIORITY"]
        app.config["MTA_STS_MX"] = toml_config[mode]["MTA_STS_MX"]
        app.config["SPF_RECORD"] = toml_config[mode]["SPF_RECORD"]
        app.config["DKIM_CNAME_RECORD1"] = toml_config[mode]["DKIM_CNAME_RECORD1"]
        app.config["DKIM_CNAME_RECORD2"] = toml_config[mode]["DKIM_CNAME_RECORD2"]
        app.config["DKIM_CNAME_RECORD3"] = toml_config[mode]["DKIM_CNAME_RECORD3"]
        app.config["DMARC_RECORD"] = toml_config[mode]["DMARC_RECORD"]
        app.config["SMTP_SERVER"] = toml_config[mode]["SMTP_SERVER"]
        app.config["IMAP_SERVER"] = toml_config[mode]["IMAP_SERVER"]

        # Configure security.txt fields.
        app.config["SECURITY_TXT_CONTACT"] = toml_config[mode]["SECURITY_TXT_CONTACT"]
        app.config["SECURITY_TXT_EXPIRES"] = toml_config[mode]["SECURITY_TXT_EXPIRES"]
        app.config["SECURITY_TXT_ENCRYPTION"] = toml_config[mode][
            "SECURITY_TXT_ENCRYPTION"
        ]
        app.config["SECURITY_TXT_PREFERRED_LANGUAGES"] = toml_config[mode][
            "SECURITY_TXT_PREFERRED_LANGUAGES"
        ]
        app.config["SECURITY_TXT_CANONICAL"] = toml_config[mode][
            "SECURITY_TXT_CANONICAL"
        ]

        # Configure tor and i2p addres.
        app.config["TOR_ADDRESS"] = toml_config[mode]["TOR_ADDRESS"]
        app.config["I2P_ADDRESS"] = toml_config[mode]["I2P_ADDRESS"]

        # Configure logging to file.
        if toml_config[mode]["LOGGING"]["LOG_TO_FILE"] == True:
            file_handler = FileHandler(filename=toml_config[mode]["LOGGING"]["LOGFILE"])
            file_handler.setFormatter(logging.Formatter(log_format))
            app.logger.addHandler(file_handler)

        # Configure logging to syslog.
        if toml_config[mode]["LOGGING"]["LOG_TO_SYSLOG"] == True:
            syslog_handler = logging.handlers.SysLogHandler(
                address=toml_config[mode]["LOGGING"]["SYSLOG_SERVER"]
            )
            syslog_handler.setFormatter(logging.Formatter(log_format))
            app.logger.addHandler(syslog_handler)

        # Configure loglevel.
        if toml_config[mode]["LOGGING"]["LOGLEVEL"] == "ERROR":
            app.logger.setLevel(logging.ERROR)
        elif toml_config[mode]["LOGGING"]["LOGLEVEL"] == "WARNING":
            app.logger.setLevel(logging.WARNING)
        elif toml_config[mode]["LOGGING"]["LOGLEVEL"] == "INFO":
            app.logger.setLevel(logging.INFO)
        elif toml_config[mode]["LOGGING"]["LOGLEVEL"] == "DEBUG":
            app.logger.setLevel(logging.DEBUG)
        else:
            print("Error: you need to set LOGLEVEL to ERROR/WARNING/INFO/DEBUG")
            sys.exit(1)
    else:
        print(
            "Error: you need to set env variabel MODE to PRODUCTION/TESTING/DEVELOPMENT"
        )
        sys.exit(1)

    app.secret_key = app.config["SECRET_KEY"]
    app.WTF_CSRF_SECRET_KEY = app.config["WTF_CSRF_SECRET_KEY"]
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    # app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI']

    csrf = CSRFProtect(app)

    # Serve a friendly page instead of a raw 500 when uploads exceed
    # MAX_CONTENT_LENGTH.
    @app.errorhandler(RequestEntityTooLarge)
    def _handle_request_too_large(e):
        return render_template(
            "message.html",
            headline="Upload too large",
            message="The uploaded file is larger than the allowed limit.",
        ), 413

    # Ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Import the database models.
    from ddmail_webapp.models import db

    db.init_app(app)

    # Import forms

    # Apply the blueprints to the app
    from ddmail_webapp import auth, settings, unauthenticated, well_known

    app.register_blueprint(auth.bp)
    app.register_blueprint(settings.bp)
    app.register_blueprint(unauthenticated.bp)
    app.register_blueprint(well_known.bp)

    return app
