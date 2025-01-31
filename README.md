# What is ddmail_webapp
Main web application for the DDMail project.

# What is DDMail
DDMail is a e-mail system/service that prioritize privacy and security. A current production example can be found at www.ddmail.se

# Operating system
Developt for and tested on debian 12.

# Installation
`git clone https://github.com/drzobin/ddmail_webapp.git`<br>

## Setup python virtual environments
`python -m venv [venv path]`<br>
`source [venv path]/bin/activate`

`cd ddmail_webapp/ddmail`<br>
`pip install -r requirements.txt`

## Run in development mode
`cd ddmail_webapp/ddmail`<br>
`export MODE=DEVELOPMENT`<br>
`flask --app ddmail:create_app run --host=0.0.0.0 --debug`

## Run tests in testing mode
`cd ddmail_webapp/ddmail`<br>
`export MODE=TESTING`<br>
`pytest`
