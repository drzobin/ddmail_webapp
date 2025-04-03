# What is ddmail_webapp
Main web application for the DDMail project.

## What is DDMail
DDMail is a e-mail system/service that prioritizes security. A current production example can be found at www.ddmail.se

## Operating system
Developt for and tested on debian 12.

## Installing using pip
`pip install ddmail-webapp`

## Building and installing from source using hatchling.
Step 1: clone github repo<br>
`git clone https://github.com/drzobin/ddmail_webapp [code path]`<br>
`cd [code path]`<br>
<br>
Step 2: Setup python virtual environments<br>
`python -m venv [venv path]`<br>
`source [venv path]/bin/activate`<br>
<br>
Step 3: Install package and required dependencies<br>
`pip install -e .[dev]`<br>
<br>
Step 4: Build package<br>
`python -m pip install --upgrade build`<br>
`python -m build`<br> 
<br>
Packages is now located under dist folder<br>
<br>
Step 5: Install package<br>
`pip install dist/[package name].whl`<br>

## Running in development mode
`source [ddmail_webapp venv]/bin/activate`<br>
`export MODE=DEVELOPMENT`<br>
`flask --app ddmail_webapp:create_app(config_file="[full path to config file]") run --host=127.0.0.1 --port 8000 --debug`<br>

## Testing
`cd [code path]`<br>
`pytest --cov=ddmail_webapp tests/ --config=[config file path]`

## Installation using podmon for development
Here is instruction how to install ddmail_webapp locally for development using podman.<br> 

You can run ddmail locally in Podman by following the below steps. It has been
verified to work with Podman version `4.9.3` and podman-compose `1.0.6`.

Before you start, make sure you clone the below repositories and make sure they
are located in the same directory as `ddmail_webapp`:

* https://github.com/drzobin/ddmail_email_remover
* https://github.com/drzobin/ddmail_dmcp_keyhandler
* https://github.com/drzobin/ddmail_openpgp_keyhandler
* https://github.com/drzobin/ddmail_backup_receiver

```bash
# Once the above repositories are cloned, launch ddmail.
cd ddmail/
podman compose up --build
```
