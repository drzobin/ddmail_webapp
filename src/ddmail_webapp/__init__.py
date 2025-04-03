import os
import sys
import logging
import toml
from flask import Flask
from flask_wtf.csrf import CSRFProtect
from logging.config import dictConfig
from logging import FileHandler

def create_app(config_file=None, test_config=None):
    """Create and configure an instance of the Flask application ddmail."""
    # Configure logging.
    log_format = '[%(asctime)s] %(levelname)s in %(module)s %(funcName)s %(lineno)s: %(message)s'
    dictConfig({
        'version': 1,
        'formatters': {'default': {
            'format': log_format
        }},
        'handlers': {
            'wsgi': {
                'class': 'logging.StreamHandler',
                'stream': 'ext://flask.logging.wsgi_errors_stream',
                'formatter': 'default',
            },
        },
        'root': {
            'level': 'INFO',
            'handlers': ['wsgi']
        }
    })

    app = Flask(__name__, instance_relative_config=True)

    toml_config = None

    # Check if config_file has been set.
    if config_file is None:
        print("Error: you need to set path to configuration file in toml format")
        sys.exit(1)

    # Parse toml config file.
    with open(config_file, 'r') as f:
        toml_config = toml.load(f)

    # Set app configurations from toml config file.
    mode = os.environ.get('MODE')
    print("Running in MODE: " + mode)

    # Apply configuration for the specific MODE.
    if mode == "PRODUCTION":
        app.config["SECRET_KEY"] = toml_config["PRODUCTION"]["SECRET_KEY"]
        app.config['SQLALCHEMY_DATABASE_URI'] = toml_config["PRODUCTION"]['SQLALCHEMY_DATABASE_URI']
        app.config["WTF_CSRF_SECRET_KEY"] = toml_config["PRODUCTION"]["WTF_CSRF_SECRET_KEY"]

        # Configure services that ddmail_webapp depend on. 
        app.config["EMAIL_REMOVER_URL"] = toml_config["PRODUCTION"]["EMAIL_REMOVER_URL"]
        app.config["EMAIL_REMOVER_PASSWORD"] = toml_config["PRODUCTION"]["EMAIL_REMOVER_PASSWORD"]
        app.config["DMCP_KEYHANDLER_URL"] = toml_config["PRODUCTION"]["DMCP_KEYHANDLER_URL"]
        app.config["DMCP_KEYHANDLER_PASSWORD"] = toml_config["PRODUCTION"]["DMCP_KEYHANDLER_PASSWORD"]
        app.config["OPENPGP_KEYHANDLER_URL"] = toml_config["PRODUCTION"]["OPENPGP_KEYHANDLER_URL"]
        app.config["OPENPGP_KEYHANDLER_PASSWORD"] = toml_config["PRODUCTION"]["OPENPGP_KEYHANDLER_PASSWORD"]

        # Configure payment information.
        app.config["PAYMENT_BANKGIRO"] = toml_config["PRODUCTION"]["PAYMENT_BANKGIRO"]
        
        # Configure dns record checked when adding account/own domains.
        app.config["MX_RECORD_HOST"] = toml_config["PRODUCTION"]["MX_RECORD_HOST"]
        app.config["MX_RECORD_PRIORITY"] = toml_config["PRODUCTION"]["MX_RECORD_PRIORITY"]
        app.config["SPF_RECORD"] = toml_config["PRODUCTION"]["SPF_RECORD"]
        app.config["DKIM_RECORD"] = toml_config["PRODUCTION"]["DKIM_RECORD"]
        app.config["DMARC_RECORD"] = toml_config["PRODUCTION"]["DMARC_RECORD"]

        # Configure tor and i2p addres.
        app.config["TOR_ADDRESS"] = toml_config["PRODUCTION"]["TOR_ADDRESS"]
        app.config["I2P_ADDRESS"] = toml_config["PRODUCTION"]["I2P_ADDRESS"]

        # Configure logfile.
        file_handler = FileHandler(filename=toml_config["PRODUCTION"]["LOGFILE"])
        file_handler.setFormatter(logging.Formatter(log_format))
        app.logger.addHandler(file_handler)
        
        # Configure loglevel.
        if toml_config["PRODUCTION"]["LOGLEVEL"] == "ERROR":
            app.logger.setLevel(logging.ERROR)
        elif toml_config["PRODUCTION"]["LOGLEVEL"] == "WARNING":
            app.logger.setLevel(logging.WARNING)
        elif toml_config["PRODUCTION"]["LOGLEVEL"] == "INFO":
            app.logger.setLevel(logging.INFO)
        elif toml_config["PRODUCTION"]["LOGLEVEL"] == "DEBUG":
            app.logger.setLevel(logging.DEBUG)
        else:
            print("Error: you need to set LOGLEVEL to ERROR/WARNING/INFO/DEBUG")
            sys.exit(1)
    elif mode == "TESTING":
        app.config["SECRET_KEY"] = toml_config["TESTING"]["SECRET_KEY"]
        app.config['SQLALCHEMY_DATABASE_URI'] = toml_config["TESTING"]['SQLALCHEMY_DATABASE_URI']
        app.config["WTF_CSRF_SECRET_KEY"] = toml_config["TESTING"]["WTF_CSRF_SECRET_KEY"]

        # Configure services that ddmail_webapp depend on. 
        app.config["EMAIL_REMOVER_URL"] = toml_config["TESTING"]["EMAIL_REMOVER_URL"]
        app.config["EMAIL_REMOVER_PASSWORD"] = toml_config["TESTING"]["EMAIL_REMOVER_PASSWORD"]
        app.config["DMCP_KEYHANDLER_URL"] = toml_config["TESTING"]["DMCP_KEYHANDLER_URL"]
        app.config["DMCP_KEYHANDLER_PASSWORD"] = toml_config["TESTING"]["DMCP_KEYHANDLER_PASSWORD"]
        app.config["OPENPGP_KEYHANDLER_URL"] = toml_config["TESTING"]["OPENPGP_KEYHANDLER_URL"]
        app.config["OPENPGP_KEYHANDLER_PASSWORD"] = toml_config["TESTING"]["OPENPGP_KEYHANDLER_PASSWORD"]

        # Configure payment information.
        app.config["PAYMENT_BANKGIRO"] = toml_config["TESTING"]["PAYMENT_BANKGIRO"]
        
        # Configure dns record checked when adding account/own domains.
        app.config["MX_RECORD_HOST"] = toml_config["TESTING"]["MX_RECORD_HOST"]
        app.config["MX_RECORD_PRIORITY"] = toml_config["TESTING"]["MX_RECORD_PRIORITY"]
        app.config["SPF_RECORD"] = toml_config["TESTING"]["SPF_RECORD"]
        app.config["DKIM_RECORD"] = toml_config["TESTING"]["DKIM_RECORD"]
        app.config["DMARC_RECORD"] = toml_config["TESTING"]["DMARC_RECORD"]

        # Configure tor and i2p addres.
        app.config["TOR_ADDRESS"] = toml_config["TESTING"]["TOR_ADDRESS"]
        app.config["I2P_ADDRESS"] = toml_config["TESTING"]["I2P_ADDRESS"]

        # Configure logfile.
        file_handler = FileHandler(filename=toml_config["TESTING"]["LOGFILE"])
        file_handler.setFormatter(logging.Formatter(log_format))
        app.logger.addHandler(file_handler)

        # Configure loglevel.
        if toml_config["TESTING"]["LOGLEVEL"] == "ERROR":
            app.logger.setLevel(logging.ERROR)
        elif toml_config["TESTING"]["LOGLEVEL"] == "WARNING":
            app.logger.setLevel(logging.WARNING)
        elif toml_config["TESTING"]["LOGLEVEL"] == "INFO":
            app.logger.setLevel(logging.INFO)
        elif toml_config["TESTING"]["LOGLEVEL"] == "DEBUG":
            app.logger.setLevel(logging.DEBUG)
        else:
            print("Error: you need to set LOGLEVEL to ERROR/WARNING/INFO/DEBUG")
            sys.exit(1)
    elif mode == "DEVELOPMENT":
        app.config["SECRET_KEY"] = toml_config["DEVELOPMENT"]["SECRET_KEY"]
        app.config['SQLALCHEMY_DATABASE_URI'] = toml_config["DEVELOPMENT"]['SQLALCHEMY_DATABASE_URI']
        app.config["WTF_CSRF_SECRET_KEY"] = toml_config["DEVELOPMENT"]["WTF_CSRF_SECRET_KEY"]

        # Configure services that ddmail_webapp depend on. 
        app.config["EMAIL_REMOVER_URL"] = toml_config["DEVELOPMENT"]["EMAIL_REMOVER_URL"]
        app.config["EMAIL_REMOVER_PASSWORD"] = toml_config["DEVELOPMENT"]["EMAIL_REMOVER_PASSWORD"]
        app.config["DMCP_KEYHANDLER_URL"] = toml_config["DEVELOPMENT"]["DMCP_KEYHANDLER_URL"]
        app.config["DMCP_KEYHANDLER_PASSWORD"] = toml_config["DEVELOPMENT"]["DMCP_KEYHANDLER_PASSWORD"]
        app.config["OPENPGP_KEYHANDLER_URL"] = toml_config["DEVELOPMENT"]["OPENPGP_KEYHANDLER_URL"]
        app.config["OPENPGP_KEYHANDLER_PASSWORD"] = toml_config["DEVELOPMENT"]["OPENPGP_KEYHANDLER_PASSWORD"]

        # Configure payment information.
        app.config["PAYMENT_BANKGIRO"] = toml_config["DEVELOPMENT"]["PAYMENT_BANKGIRO"]
        
        # Configure dns record checked when adding account/own domains.
        app.config["MX_RECORD_HOST"] = toml_config["DEVELOPMENT"]["MX_RECORD_HOST"]
        app.config["MX_RECORD_PRIORITY"] = toml_config["DEVELOPMENT"]["MX_RECORD_PRIORITY"]
        app.config["SPF_RECORD"] = toml_config["DEVELOPMENT"]["SPF_RECORD"]
        app.config["DKIM_RECORD"] = toml_config["DEVELOPMENT"]["DKIM_RECORD"]
        app.config["DMARC_RECORD"] = toml_config["DEVELOPMENT"]["DMARC_RECORD"]
        
        # Configure tor and i2p addres.
        app.config["TOR_ADDRESS"] = toml_config["DEVELOPMENT"]["TOR_ADDRESS"]
        app.config["I2P_ADDRESS"] = toml_config["DEVELOPMENT"]["I2P_ADDRESS"]

        # Configure logfile.
        file_handler = FileHandler(filename=toml_config["DEVELOPMENT"]["LOGFILE"])
        file_handler.setFormatter(logging.Formatter(log_format))
        app.logger.addHandler(file_handler)

        # Configure loglevel.
        if toml_config["DEVELOPMENT"]["LOGLEVEL"] == "ERROR":
            app.logger.setLevel(logging.ERROR)
        elif toml_config["DEVELOPMENT"]["LOGLEVEL"] == "WARNING":
            app.logger.setLevel(logging.WARNING)
        elif toml_config["DEVELOPMENT"]["LOGLEVEL"] == "INFO":
            app.logger.setLevel(logging.INFO)
        elif toml_config["DEVELOPMENT"]["LOGLEVEL"] == "DEBUG":
            app.logger.setLevel(logging.DEBUG)
        else:
            print("Error: you need to set LOGLEVEL to ERROR/WARNING/INFO/DEBUG")
            sys.exit(1)
    else:
        print("Error: you need to set env variabel MODE to PRODUCTION/TESTING/DEVELOPMENT")
        sys.exit(1)
    
    app.secret_key = app.config["SECRET_KEY"]
    app.WTF_CSRF_SECRET_KEY = app.config["WTF_CSRF_SECRET_KEY"]
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    #app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI']

    csrf = CSRFProtect(app)

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
