# What is ddmail_webapp
Main web application for the ddmail project.

# What is ddmail
ddmail is a e-mail system/service that prioritize privacy and security. A current production example can be found at www.ddmail.se

# Operating system
Developt for and tested on debian 12.

## Podman

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
