# What is ddmail_webapp
Main web application for the ddmail project.

# What is ddmail
ddmail is a e-mail system/service that prioritize privacy and security. A current production example can be found at www.ddmail.se

# Operating system
Developt for and tested on debian 12.

## Run in development mode.
cd ddmail_webapp/ddmail
export MODE=DEVELOPMENT
flask --app ddmail:create_app run --host=0.0.0.0 --debug

## Run tests in testing mode.
cd ddmail_webapp/ddmail
export MODE=TESTING
pytest
