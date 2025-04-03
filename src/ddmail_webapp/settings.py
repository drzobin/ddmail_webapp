import requests
import base64
from flask import Blueprint, session, render_template, request, current_app, redirect, url_for
from argon2 import PasswordHasher
from ddmail_webapp.auth import is_athenticated, generate_password, generate_token
from ddmail_webapp.models import db, Email, Openpgp_public_key, Account_domain, Alias, Global_domain, User
from ddmail_webapp.forms import EmailForm, AliasForm, DomainForm, EmailPasswordForm
import ddmail_validators.validators as validators

bp = Blueprint("settings", __name__, url_prefix="/")

@bp.route("/settings")
def settings():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    return render_template('settings.html', current_user = current_user)

@bp.route("/settings/usage_and_funds", methods=['GET'])
def usage_and_funds():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not authenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    return render_template('settings_usage_and_funds.html',account = current_user.account, current_user = current_user)

@bp.route("/settings/payment", methods=['GET'])
def payment():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not authenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    payment_bankgiro = current_app.config["PAYMENT_BANKGIRO"]

    return render_template('settings_payment.html', payment_bankgiro = payment_bankgiro, payment_token = current_user.account.payment_token, current_user = current_user)

@bp.route("/settings/payment_token", methods=['GET'])
def payment_token():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    return render_template('settings_payment_token.html',payment_token = current_user.account.payment_token, current_user = current_user)

@bp.route("/settings/change_password_on_user", methods=['POST', 'GET'])
def settings_change_password_on_user():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Change user password error",message="Failed to change users password beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        return render_template('settings_change_password_on_user.html',current_user = current_user)
    elif request.method == 'POST':
        # Generate new password for user.
        cleartext_password = generate_password(24)

        # Generate password hashes for password.
        ph = PasswordHasher()
        password_hash = ph.hash(cleartext_password)

        # Save the new password hash to db.
        user = db.session.query(User).filter(User.account_id == current_user.account_id, User.id == current_user.id ,User.user == current_user.user).first()
        user.password_hash = password_hash
        db.session.commit()

        current_app.logger.debug("user " + current_user.user + " belonging to account " + current_user.account.account +  " changed password")
        return render_template('message.html',headline="Change password on user",message="Successfully changed password on user: " + current_user.user + " to new password: " + cleartext_password ,current_user=current_user)

@bp.route("/settings/change_key_on_user", methods=['POST', 'GET'])
def settings_change_key_on_user():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Change user key error",message="Failed to change users key beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        return render_template('settings_change_key_on_user.html',current_user = current_user)
    elif request.method == 'POST':
        # Generate new key for user.
        cleartext_password_key = generate_password(4096)

        # Generate password hashes for password key.
        ph = PasswordHasher()
        password_key_hash = ph.hash(cleartext_password_key)

        # Save the new key hash to db.
        user = db.session.query(User).filter(User.account_id == current_user.account_id, User.id == current_user.id ,User.user == current_user.user).first()
        user.password_key_hash = password_key_hash
        db.session.commit()

        current_app.logger.debug("changed key on " + current_user.user + " belonging to account " + current_user.account.account)
        return render_template('message.html',headline="Change key on user",message="Successfully changed key on user: " + current_user.user + " to new key: " + cleartext_password_key ,current_user=current_user)


@bp.route("/settings/add_user_to_account", methods=['POST', 'GET'])
def settings_add_user_to_account():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Add email error",message="Failed to add user beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        return render_template('settings_add_user_to_account.html',current_user = current_user)

    if request.method == 'POST':
        ph = PasswordHasher()

        # Generate all the user data.
        user = generate_token(12)
        cleartext_password = generate_password(24)
        cleartext_password_key = generate_password(4096)

        # Generate password hashes for password and password-key.
        password_hash = ph.hash(cleartext_password)
        password_key_hash = ph.hash(cleartext_password_key)

        # Add the user data to the db.
        new_user = User(account_id=current_user.account_id, user=user, password_hash=password_hash,password_key_hash=password_key_hash)
        db.session.add(new_user)
        db.session.commit()

        # Give the data to the user.
        current_app.logger.debug("user " + current_user.user + " was added to account " + current_user.account.account)
        return render_template('settings_added_user_to_account.html',current_user=current_user,account=current_user.account.account,user=user,cleartext_password=cleartext_password,cleartext_password_key=cleartext_password_key)

@bp.route("/settings/show_account_users")
def settings_show_account_users():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Show account users error",message="Failed to show account users beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    users = db.session.query(User).filter(User.account_id == current_user.account_id)

    current_app.logger.debug("show users for account " + current_user.account.account)
    return render_template('settings_show_account_users.html',users=users, current_user = current_user)

@bp.route("/settings/remove_account_user", methods=['POST', 'GET'])
def settings_remove_account_user():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Remove account user error",message="Failed to remove account user beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        users = db.session.query(User).filter(User.account_id == current_user.account_id)

        return render_template('settings_remove_account_user.html',users=users, current_user=current_user)

    if request.method == 'POST':
        remove_user_from_form = request.form["remove_user"].strip()

        # Validate user data from form.
        if validators.is_username_allowed(remove_user_from_form) == False:
            current_app.logger.warning("user " + remove_user_from_form + " can not be removed beacuse string validation failed")
            return render_template('message.html',headline="Remove user error",message="Failed to removed account user, illigal character in string.",current_user=current_user)

        # Check that user already exist in db and is owned by current account.
        is_user_mine = db.session.query(User).filter(User.user == remove_user_from_form, User.account_id == current_user.account_id).count()
        if is_user_mine != 1:
            current_app.logger.warning("user " + current_user.user + " can not be removed beacuse user is not in db or is not owned by this account")
            return render_template('message.html',headline="Remove user error",message="Failed to removed account user, validation failed.",current_user=current_user)

        # Do not allow to remove current loged in user.
        if remove_user_from_form == current_user.user:
            current_app.logger.warning("user " + current_user.user + " can not be removed beacuse user are logged in as this user")
            return render_template('message.html',headline="Remove user error",message="Failed to remove account user, you can not remove the same user as you are logged in as.",current_user=current_user)

        # Remove email account from db.
        db.session.query(User).filter(User.account_id == current_user.account_id, User.user == remove_user_from_form).delete()
        db.session.commit()

        current_app.logger.debug("user " + current_user.user + " was removed, belonged to account " + current_user.account.account)
        return render_template('message.html',headline="Remove user",message="Successfully removed user.",current_user=current_user)

@bp.route("/settings/add_email", methods=['POST', 'GET'])
def settings_add_email():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Add email error",message="Failed to add email beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    form = EmailForm()
    if request.method == 'GET':

        # Get the accounts domains.
        account_domains = db.session.query(Account_domain.domain).filter(Account_domain.account_id == current_user.account_id)
        global_domains = db.session.query(Global_domain.domain).filter(Global_domain.is_enabled == True)

        domains = account_domains.union(global_domains)

        return render_template('settings_add_email.html',form=form, current_user = current_user, domains=domains)

    if request.method == 'POST':
        if not form.validate_on_submit():
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " failed to add email beacuse csrf validation failed")
            return render_template('message.html',headline="Add email error",message="Failed to add email, csrf validation failed.",current_user=current_user)
        else:
            email_from_form = form.email.data.strip()
            domain_from_form = form.domain.data.strip()

            add_email_from_form = email_from_form + "@" + domain_from_form

            # Validate email from form.
            if validators.is_email_allowed(add_email_from_form) == False:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " failed to add email " + add_email_from_form + " beacuse validation failed")
                return render_template('message.html',headline="Add email error",message="Failed to add email, email validation failed.",current_user=current_user)

            # Validate domain part of email from form.
            validate_email_domain = add_email_from_form.split('@')
            if validators.is_domain_allowed(validate_email_domain[1]) == False:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " failed to add email " + add_email_from_form + " beacuse domain is not in db")
                return render_template('message.html',headline="Add email error",message="Failed to add email, domain validation failed.",current_user=current_user)

            # Check if domain is global.
            is_domain_global = db.session.query(Global_domain).filter(Global_domain.domain == validate_email_domain[1], Global_domain.is_enabled == True).count()

            # Check if domain is owned by the account.
            is_domain_mine = db.session.query(Account_domain).filter(Account_domain.domain == validate_email_domain[1], Account_domain.account_id == current_user.account_id).count()

            if is_domain_mine != 1 and is_domain_global != 1:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " failed to add email " + add_email_from_form + " beacuse domain is not in db")
                return render_template('message.html',headline="Add email error",message="Failed to add email, domain is not active in our system.",current_user=current_user)

            # Check that email does not already exist in emails table in db.
            is_email_uniq = db.session.query(Email).filter(Email.email == add_email_from_form).count()
            if is_email_uniq != 0:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " failed to add email " + add_email_from_form + " beacuse email aldready exist as email")
                return render_template('message.html',headline="Add email error",message="Failed to add email, email already exist.",current_user=current_user)

            # Check that email does not already exist in alias table in db.
            is_email_uniq = db.session.query(Alias).filter(Alias.src_email == add_email_from_form).count()
            if is_email_uniq != 0:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " failed to add email " + add_email_from_form + " beacuse email already exist as alias")
                return render_template('message.html',headline="Add email error",message="Failed to add email, email already exist.",current_user=current_user)

            # Generate password.
            cleartext_password = generate_password(24)

            # Hash the password SSHA512.
            ph = PasswordHasher(time_cost=3,memory_cost=65536,parallelism=1)
            password_hash = ph.hash(cleartext_password)

            # Get the domain id and add the new email account to db.
            if is_domain_mine == 1:
                account_domain = db.session.query(Account_domain).filter(Account_domain.domain == validate_email_domain[1]).first()
                new_email = Email(account_id=int(current_user.account_id), email=add_email_from_form,password_hash=password_hash,storage_space_mb=0,account_domain_id=account_domain.id)
                db.session.add(new_email)
                db.session.commit()
            elif is_domain_global == 1:
                global_domain = db.session.query(Global_domain).filter(Global_domain.domain == validate_email_domain[1]).first()
                new_email = Email(account_id=int(current_user.account_id), email=add_email_from_form,password_hash=password_hash,storage_space_mb=0,global_domain_id=global_domain.id)
                db.session.add(new_email)
                db.session.commit()

            # Create encryptions keys and set password for key.
            dmcp_keyhandler_url = current_app.config["DMCP_KEYHANDLER_URL"] + "/create_key"
            dmcp_keyhandler_password = current_app.config["DMCP_KEYHANDLER_PASSWORD"]
            try:
                r_respone = requests.post(dmcp_keyhandler_url, {"email":add_email_from_form,"key_password":base64.b64encode(bytes(cleartext_password, 'utf-8')),"password":dmcp_keyhandler_password}, timeout=5)
            except requests.exceptions.ConnectionError:
                db.session.query(Email).filter(Email.account_id == int(current_user.account_id), Email.email == add_email_from_form).delete()
                db.session.commit()
                
                current_app.logger.error("user " + current_user.user + " account " + current_user.account.account + " failed to add email " + add_email_from_form + " beacuse dmcp keyhandler service is unavalible")
                return render_template('message.html',headline="Add Email Account Error",message="Failed to add email account beacuse dmcp keyhandler service is unavalible.",current_user=current_user)
        
            # Check if password protected encryption key creation was successfull.
            if r_respone.status_code != 200 or r_respone.content != b'done':
                db.session.query(Email).filter(Email.account_id == int(current_user.account_id), Email.email == add_email_from_form).delete()
                db.session.commit()
                
                current_app.logger.error("user " + current_user.user + " account " + current_user.account.account + " failed to add email " + add_email_from_form + " error when creating encryption key")
                return render_template('message.html',headline="Add email error",message="Failed trying to create password protected encryptions keys.",current_user=current_user)

            current_app.logger.debug("user " + current_user.user + " account " + current_user.account.account + " added email " + add_email_from_form)
            return render_template('message.html',headline="Add Email Account",message="Successfully added email: " + add_email_from_form + " with password: " + cleartext_password ,current_user=current_user)

@bp.route("/settings/show_email")
def settings_show_email():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Show email error",message="Failed to show email beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    emails = db.session.query(Email).filter(Email.account_id == current_user.account_id)

    current_app.logger.debug("show emails for account " + current_user.account.account)
    return render_template('settings_show_email.html',emails=emails, current_user = current_user)

@bp.route("/settings/remove_email", methods=['POST', 'GET'])
def settings_remove_email():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Remove email error",message="Failed to remove email beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        emails = db.session.query(Email).filter(Email.account_id == current_user.account_id)

        return render_template('settings_remove_email.html',emails=emails, current_user=current_user)
    if request.method == 'POST':
        remove_email_from_form = request.form["remove_email"].strip()

        # Validate email from form.
        if validators.is_email_allowed(remove_email_from_form) == False:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " failed to remove email " + remove_email_from_form + " beacuse validation failed")
            return render_template('message.html',headline="Remove email error",message="Failed to removed email, validation failed.",current_user=current_user)

        # Validate domain part of email from form.
        validate_email_domain = remove_email_from_form.split('@')
        domain = validate_email_domain[1]
        if validators.is_domain_allowed(domain) == False:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " failed to remove email " + remove_email_from_form + " beacuse domain validation failed")
            return render_template('message.html',headline="Remove email error",message="Failed to removed email, validation failed.",current_user=current_user)

        # Check that email already exist in db and is owned by current user.
        is_email_mine = db.session.query(Email).filter(Email.email == remove_email_from_form, Email.account_id == current_user.account_id).count()
        if is_email_mine != 1:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " failed to remove email " + remove_email_from_form + " beacuse domain is not in db or is not owned by account")
            return render_template('message.html',headline="Remove email error",message="Failed to removed email, validation failed.",current_user=current_user)

        # Remove email account from db.
        db.session.query(Email).filter(Email.account_id == current_user.account_id, Email.email == remove_email_from_form).delete()
        db.session.commit()

        # Remove email account data from storage with email_remover.
        email_remover_url = current_app.config["EMAIL_REMOVER_URL"]
        email_remover_password = current_app.config["EMAIL_REMOVER_PASSWORD"]
        try:
            r_respone = requests.post(email_remover_url, {"password":email_remover_password,"domain":domain,"email":remove_email_from_form}, timeout=5)
        except requests.exceptions.ConnectionError:
            current_app.logger.error("user " + current_user.user + " account " + current_user.account.account + " failed to remove email " + remove_email_from_form + " beacuse ddmail email remover service is unavalible")
            return render_template('message.html',headline="Remove Email Error",message="Failed to removed email beacuse email remover service is unavalible.",current_user=current_user)

        
        # Check if removal was successfull.
        if r_respone.status_code != 200 or r_respone.content != b'done':
            current_app.logger.error("user " + current_user.user + " account " + current_user.account.account + " failed to remove email " + remove_email_from_form + " beacuse ddmail email remover service returned error")
            return render_template('message.html',headline="Remove email error",message="Failed to remove data on disc for email account.",current_user=current_user)
        
        current_app.logger.debug("user " + current_user.user + " account " + current_user.account.account + " removed email " + remove_email_from_form)
        return render_template('message.html',headline="Remove Email Account",message="Successfully removed email.",current_user=current_user)

@bp.route("/settings/change_password_on_email", methods=['POST', 'GET'])
def settings_change_password_on_email():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    form = EmailPasswordForm()
    if request.method == 'GET':
        emails = db.session.query(Email).filter(Email.account_id == current_user.account_id)

        return render_template('settings_change_password_on_email.html',form=form,emails=emails, current_user=current_user)

    if request.method == 'POST':
        ph = PasswordHasher()

        change_password_on_email_from_form = request.form["change_password_on_email"].strip()
        current_cleartext_password_from_form = request.form["email_password"].strip()

        # Validate email from form.
        if validators.is_email_allowed(change_password_on_email_from_form) == False:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " failed to change password on email " + change_password_on_email_from_form + " beacuse validation failed")
            return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account, validation failed.",current_user=current_user)

        # Validate domain part of email from form.
        validate_email_domain = change_password_on_email_from_form.split('@')
        if validators.is_domain_allowed(validate_email_domain[1]) == False:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " failed to change password on email " + change_password_on_email_from_form + " beacuse domain validation failed")
            return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account, validation failed.",current_user=current_user)
        
        # Validate current password from form.
        if validators.is_password_allowed(current_cleartext_password_from_form) == False:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " failed to change password on email " + change_password_on_email_from_form + " beacuse current password validation failed")
            return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account, validation failed on current password.",current_user=current_user)

        # Check that email already exist in db and is owned by current user.
        is_email_mine = db.session.query(Email).filter(Email.email == change_password_on_email_from_form, Email.account_id == current_user.account_id).count()
        if is_email_mine != 1:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " failed to change password on email " + change_password_on_email_from_form + " beacuse emails is not in db or is not owned by current user")
            return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account, validation failed.",current_user=current_user)

        # Get current password hash for email account.
        email_from_db = db.session.query(Email).filter(Email.email == change_password_on_email_from_form, Email.account_id == current_user.account_id).first()

        # Check current password is correct.
        try:
            if ph.verify(email_from_db.password_hash, current_cleartext_password_from_form) != True:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " failed to change password on email " + change_password_on_email_from_form + " beacuse current password is wrong")
                return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account, current email account password is wrong.",current_user=current_user)
        except:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " failed to change password on email " + change_password_on_email_from_form + " beacuse current password is wrong")
            return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account, current email account password is wrong.",current_user=current_user)

        # Generate password.
        cleartext_password = generate_password(24)

        # Change password on encryption key.
        dmcp_keyhandler_url = current_app.config["DMCP_KEYHANDLER_URL"] + "/change_password_on_key"
        dmcp_keyhandler_password = current_app.config["DMCP_KEYHANDLER_PASSWORD"]
        try:
            r_respone = requests.post(dmcp_keyhandler_url, {"email":change_password_on_email_from_form,"current_key_password":base64.b64encode(bytes(current_cleartext_password_from_form, 'utf-8')),"new_key_password":base64.b64encode(bytes(cleartext_password, 'utf-8')),"password":dmcp_keyhandler_password}, timeout=5)
        except requests.exceptions.ConnectionError:
            current_app.logger.error("user " + current_user.user + " account " + current_user.account.account + " failed to change password on email " + change_password_on_email_from_form + " beacuse dmcp keyhandler service is unavalible")
            return render_template('message.html',headline="Change Password On Email Account Error",message="Failed to change password on email account becuse dmcp keyhandler is unavalible",current_user=current_user)

        # Check if password on encryption key change was successfull.
        if r_respone.status_code != 200 or r_respone.content != b'done':
            current_app.logger.error("user " + current_user.user + " account " + current_user.account.account + " failed to change password on email " + change_password_on_email_from_form + " beacuse dmcp keyhandler service returned error")
            return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account, failed to change password on encryption key.",current_user=current_user)

        # Hash the password argon2.
        ph = PasswordHasher(time_cost=3,memory_cost=65536,parallelism=1)
        password_hash = ph.hash(cleartext_password)

        # Change password on email account from db.
        email = db.session.query(Email).filter(Email.account_id == current_user.account_id, Email.email == change_password_on_email_from_form).first()
        email.password_hash = password_hash
        db.session.commit()

        current_app.logger.debug("user " + current_user.user + " account " + current_user.account.account + " change password on email " + change_password_on_email_from_form)
        return render_template('message.html',headline="Change password on Email Account",message="Successfully changed password on email account: " + change_password_on_email_from_form + " to new password: " + cleartext_password ,current_user=current_user)

@bp.route("/settings/show_openpgp_public_keys")
def settings_show_openpgp_public_keys():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Show openpgp public keys error",message="Failed to show openpgp public keys beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    keys = db.session.query(Openpgp_public_key).filter(Openpgp_public_key.account_id == current_user.account_id)

    current_app.logger.debug("user " + current_user.user + " account " + current_user.account.account + " show openpgp public keys")
    return render_template('settings_show_openpgp_public_keys.html',keys=keys, current_user = current_user)

@bp.route("/settings/upload_openpgp_public_key", methods=['POST', 'GET'])
def settings_upload_openpgp_public_key():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Upload openpgp public key error",message="Failed to upload openpgp public key beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        return render_template('settings_upload_openpgp_public_key.html', current_user = current_user)

    if request.method == 'POST':
        file = request.files['openpgp_public_key']
        openpgp_public_key = file.read().strip().decode("utf-8")

        # Check if public key file is empty.
        if openpgp_public_key == None:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " openpgp public key i empty")
            return render_template('message.html',headline="Upload openpgp public key error",message="Failed to upload openpgp public key beacuse uploaded public key i empty",current_user=current_user)

        # Validate openpgp public key data.
        if validators.is_openpgp_public_key_allowed(openpgp_public_key) != True:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " openpgp public key " + openpgp_public_key + " validation failed")
            return render_template('message.html',headline="Upload openpgp public key error",message="Failed to upload openpgp public key beacuse validation failed",current_user=current_user)

        # Send openpgp public key to ddmail openpgp keyhandler service.
        openpgp_keyhandler_url = current_app.config["OPENPGP_KEYHANDLER_URL"] + "/upload_public_key"
        openpgp_keyhandler_password = current_app.config["OPENPGP_KEYHANDLER_PASSWORD"]
        try:
            r_respone = requests.post(openpgp_keyhandler_url, {"public_key":openpgp_public_key,"keyring":current_user.account.account,"password":openpgp_keyhandler_password}, timeout=5)
        except requests.exceptions.ConnectionError:
            current_app.logger.error("user " + current_user.user + " account " + current_user.account.account + " faild to upload openpgp public key beacuse openpgp keyhandler service do not ansver")
            return render_template('message.html',headline="Upload OpenPGP Public Key Error",message="Failed to upload openpgp public key beacuse openpgp keyhandler service do not answer.",current_user=current_user)
            
        # Check if upload was successfull.
        if r_respone.status_code != 200 or "done fingerprint: " not in str(r_respone.content):
            current_app.logger.error("user " + current_user.user + " account " + current_user.account.account + " faild to upload openpgp public key beacuse openpgp keyhandler service returned error")
            return render_template('message.html',headline="Upload openpgp public key error",message="Failed to upload openpgp public key.",current_user=current_user)

        # Get fingerprint of uploaded openpgp public key.
        fingerprint = str(r_respone.content, encoding="utf-8").replace("done fingerprint: ","")
        fingerprint = fingerprint.strip()

        # Validate fingerprint.
        if validators.is_openpgp_key_fingerprint_allowed(fingerprint) != True:
            current_app.logger.error("user " + current_user.user + " account " + current_user.account.account + " faild to upload openpgp public key beacuse openpgp keyhandler service returned fingerprint " + fingerprint  + " that failed validation")
            return render_template('message.html',headline="Upload openpgp public key error",message="Openpgp public key fingerprint validation failed.",current_user=current_user)

        # Check that openpgp public key fingerprint do not exist in db
        is_fingerprint_uniq = db.session.query(Openpgp_public_key).filter(Openpgp_public_key.account_id == current_user.account_id, Openpgp_public_key.fingerprint == fingerprint).count()
        if is_fingerprint_uniq != 0:
            current_app.logger.error("user " + current_user.user + " account " + current_user.account.account + " faild to upload openpgp public key beacuse openpgp keyhandler service returned fingerprint " + fingerprint  + " that already exist in db")
            return render_template('message.html',headline="Upload openpgp public key error",message="Openpgp public key fingerprint already exist in db",current_user=current_user)

        # Insert fingerprint to db.
        new_openpgp_public_key = Openpgp_public_key(account_id=current_user.account_id, fingerprint=fingerprint)
        db.session.add(new_openpgp_public_key)
        db.session.commit()

        current_app.logger.debug("user " + current_user.user + " account " + current_user.account.account + " uploaded openpgp public key with fingerprint" + fingerprint)
        return render_template('message.html',headline="Upload openpgp public key",message="Succesfully upload openpgp public key.",current_user=current_user)

@bp.route("/settings/remove_openpgp_public_key", methods=['POST', 'GET'])
def settings_remove_openpgp_public_key():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Upload openpgp public key error",message="Failed to upload openpgp public key beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        fingerprints = db.session.query(Openpgp_public_key).filter(Openpgp_public_key.account_id == current_user.account_id)
        
        return render_template('settings_remove_openpgp_public_key.html',fingerprints = fingerprints, current_user = current_user)

    if request.method == 'POST':
        fingerprint = request.form["fingerprint"].strip()

        # Check if fingeprint from form is empty.
        if fingerprint == None or fingerprint == "":
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " fingerprint is empty")
            return render_template('message.html',headline="Remove openpgp public key error",message="Failed to remove openpgp public key beacuse form is empty",current_user=current_user)

        # Validate fingerprint.
        if validators.is_openpgp_key_fingerprint_allowed(fingerprint) != True:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " fingerprint " + fingerprint  + " validation failed")
            return render_template('message.html',headline="Remove openpgp public key error",message="Openpgp public key fingerprint validation failed.",current_user=current_user)

        # Check that openpgp public key fingerprint exist in db and is owned by current account
        is_fingerprint_mine = db.session.query(Openpgp_public_key).filter(Openpgp_public_key.account_id == current_user.account_id, Openpgp_public_key.fingerprint == fingerprint).count()
        if is_fingerprint_mine != 1:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " fingerprint " + fingerprint  + " is not in db or is not owned by current user")
            return render_template('message.html',headline="Remove openpgp public key error",message="Openpgp public key fingerprint do not exist in database or is not owned by your account",current_user=current_user)

        # Send openpgp public key fingerprint to ddmail openpgp keyhandler service to remove openpgp public key from account keyring.
        openpgp_keyhandler_url = current_app.config["OPENPGP_KEYHANDLER_URL"] + "/remove_public_key"
        openpgp_keyhandler_password = current_app.config["OPENPGP_KEYHANDLER_PASSWORD"]
        try:
            r_respone = requests.post(openpgp_keyhandler_url, {"fingerprint":fingerprint,"keyring":current_user.account.account,"password":openpgp_keyhandler_password}, timeout=5)
        except requests.exceptions.ConnectionError:
            current_app.logger.error("user " + current_user.user + " account " + current_user.account.account + " removing openpgp public key with fingerprint " + fingerprint  + " failed beacuse openpgp keyhandler service do not answer")
            return render_template('message.html',headline="Remove OpenPGP Public Key Error",message="Failed to remove openpgp public key beacuse openpgp keyhandler service do not answer.",current_user=current_user)
        
        # Check if remove was succesfull.
        if r_respone.status_code != 200 or str(r_respone.content) == "done":
            current_app.logger.error("user " + current_user.user + " account " + current_user.account.account + " removing openpgp public key with fingerprint " + fingerprint  + " failed beacuse openpgp keyhandler service returned error")
            return render_template('message.html',headline="Remove openpgp public key error",message="Failed to remove openpgp public key.",current_user=current_user)

        # Remove openpgp public key from database.
        db.session.query(Openpgp_public_key).filter(Openpgp_public_key.account_id == current_user.account_id, Openpgp_public_key.fingerprint == fingerprint).delete()
        db.session.commit()

        # Check that openpgp public key fingerprint do not exist in database anymore.
        is_fingerprint = db.session.query(Openpgp_public_key).filter(Openpgp_public_key.account_id == current_user.account_id, Openpgp_public_key.fingerprint == fingerprint).count()
        if is_fingerprint != 0:
            current_app.logger.error("user " + current_user.user + " account " + current_user.account.account + " fingerprint " + fingerprint  + " still exist in db")
            return render_template('message.html',headline="Remove openpgp public key error",message="Openpgp public key fingerprint still exist in database.",current_user=current_user)

        current_app.logger.debug("user " + current_user.user + " account " + current_user.account.account + " openpgp public key with fingerprint " + fingerprint  + " was removed")
        return render_template('message.html',headline="Remove OpenPGP Public Key",message="Succesfully removed OpenPGP public key.",current_user=current_user)

@bp.route("/settings/show_emails_with_activated_openpgp")
def settings_show_emails_with_activated_openpgp():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Show Emails With Activated Openpgp",message="Failed to show emails with activated OpenPGP encryption beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    emails = db.session.query(Email).filter(Email.account_id == current_user.account_id,Email.openpgp_public_key_id != None)

    current_app.logger.debug("user " + current_user.user + " account " + current_user.account.account + " show emails with active openpgp encryption")
    return render_template('settings_show_emails_with_activated_openpgp.html',emails = emails, current_user = current_user)

@bp.route("/settings/activate_openpgp_encryption", methods=['POST', 'GET'])
def settings_activate_openpgp_encryption():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Activate OpenPGP Encryption Error",message="Failed to activate OpenPGP encryption beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        fingerprints = db.session.query(Openpgp_public_key).filter(Openpgp_public_key.account_id == current_user.account_id)
        emails = db.session.query(Email).filter(Email.account_id == current_user.account_id)

        return render_template('settings_activate_openpgp_encryption.html',fingerprints = fingerprints, emails = emails, current_user = current_user)
    if request.method == 'POST':
        fingerprint = request.form["fingerprint"].strip()
        email = request.form["email"].strip()

        # Check if fingeprint from form is empty.
        if fingerprint == None or fingerprint == "":
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " fingerprint is empty")
            return render_template('message.html',headline="Activate OpenPGP Encryption Error",message="Failed to activate OpenPGP encryption beacuse fingerprint form is empty.",current_user=current_user)

        # Check if email from form is empty.
        if email == None or email == "":
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " email is empty")
            return render_template('message.html',headline="Activate OpenPGP Encryption Error",message="Failed to activate OpenPGP encryption beacuse email form is empty.",current_user=current_user)
        
        # Validate fingerprint.
        if validators.is_openpgp_key_fingerprint_allowed(fingerprint) != True:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " fingerprint " + fingerprint  + " failed validation")
            return render_template('message.html',headline="Activate OpenPGP Encryption Error",message="Failed to activate OpenPGP encryption beacuse fingerprint validation failed",current_user=current_user)

        # Validate email.
        if validators.is_email_allowed(email) == False:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " email " + email + " failed validation")
            return render_template('message.html',headline="Activate OpenPGP Encryption Error",message="Failed to activate OpenPGP encryption beacuse email validation failed.",current_user=current_user)

        # Check that openpgp public key fingerprint exist in db and is owned by current account.
        is_fingerprint_mine = db.session.query(Openpgp_public_key).filter(Openpgp_public_key.account_id == current_user.account_id, Openpgp_public_key.fingerprint == fingerprint).count()
        if is_fingerprint_mine != 1:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " fingerprint " + fingerprint  + " is not in db or is not owned by current user")
            return render_template('message.html',headline="Activate OpenPGP Encryption Error",message="Failed to activate OpenPGP encryption beacuse openpgp public key fingerprint can not be found in database",current_user=current_user)
       
       # Check that email already exist in db and is owned by current account.
        is_email_mine = db.session.query(Email).filter(Email.email == email, Email.account_id == current_user.account_id).count()
        if is_email_mine != 1:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " email " + email + " is not in db or is not owned by current user")
            return render_template('message.html',headline="Activate OpenPGP Encryption Error",message="Failed to activate OpenPGP encryption beacuse email can not be found in database",current_user=current_user)

        # Get the id of the openpgp public key record in db.
        openpgp_public_key = db.session.query(Openpgp_public_key).filter(Openpgp_public_key.account_id == current_user.account_id, Openpgp_public_key.fingerprint == fingerprint).first()

        # Activate openpgp encryption on email account in db.
        email_from_db = db.session.query(Email).filter(Email.account_id == current_user.account_id, Email.email == email).first()
        email_from_db.openpgp_public_key_id  = openpgp_public_key.id
        db.session.commit()

        # Check that openpgp encryption is actived on the specified email account.
        email_from_db = db.session.query(Email).filter(Email.account_id == current_user.account_id, Email.email == email).first()
        if email_from_db.openpgp_public_key_id != openpgp_public_key.id or openpgp_public_key.fingerprint != fingerprint:
            current_app.logger.error("user " + current_user.user + " account " + current_user.account.account + " fingerprint " + fingerprint  + " email " + email + " activation failed ")
            return render_template('message.html',headline="Activate OpenPGP Encryption Error",message="Failed to activate OpenPGP encryption",current_user=current_user)
            
        current_app.logger.debug("user " + current_user.user + " account " + current_user.account.account + " openpgp public key with fingerprint " + fingerprint  + " email " + email + " activated openpgp encryption")
        return render_template('message.html',headline="Activate Openpgp Encryption",message="Successfully activated OpenPGP encryption",current_user=current_user)

@bp.route("/settings/deactivate_openpgp_encryption", methods=['POST', 'GET'])
def settings_deactivate_openpgp_encryption():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Deactivate OpenPGP Encryption Error",message="Failed to deactivate OpenPGP encryption beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        emails = db.session.query(Email).filter(Email.account_id == current_user.account_id, Email.openpgp_public_key_id != None)

        return render_template('settings_deactivate_openpgp_encryption.html',emails = emails, current_user = current_user)
    if request.method == 'POST':
        email = request.form.get("email")

        # Check if email from form is empty.
        if email == None or email == "":
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " email is empty")
            return render_template('message.html',headline="Activate OpenPGP Encryption Error",message="Failed to activate OpenPGP encryption beacuse email form is empty.",current_user=current_user)

        # Strip email string of spaces or newline.
        email = email.strip()
        
        # Validate email.
        if validators.is_email_allowed(email) == False:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " email " + email + " failed validation")
            return render_template('message.html',headline="Activate OpenPGP Encryption Error",message="Failed to activate OpenPGP encryption beacuse email validation failed.",current_user=current_user)
       
       # Check that email already exist in db and is owned by current account.
        is_email_mine = db.session.query(Email).filter(Email.email == email, Email.account_id == current_user.account_id).count()
        if is_email_mine != 1:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " email " + email + " is not in db or is not owned by current user")
            return render_template('message.html',headline="Activate OpenPGP Encryption Error",message="Failed to activate OpenPGP encryption beacuse email can not be found in database",current_user=current_user)

        # Activate openpgp encryption on email account in db.
        email_from_db = db.session.query(Email).filter(Email.account_id == current_user.account_id, Email.email == email).first()
        email_from_db.openpgp_public_key_id  = None
        db.session.commit()

        # Check that openpgp encryption is deactived on the specified email account.
        email_from_db = db.session.query(Email).filter(Email.account_id == current_user.account_id, Email.email == email).first()
        if email_from_db.openpgp_public_key_id != None:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " email " + email + " openpgp encryption is already deactivated")
            return render_template('message.html',headline="Deactivate OpenPGP Encryption Error",message="Failed to deactivate OpenPGP encryption on this email account",current_user=current_user)
            
        current_app.logger.debug("user " + current_user.user + " account " + current_user.account.account + " email " + email + " deactivated openpgp encryption")
        return render_template('message.html',headline="Deactivate Openpgp Encryption",message="Successfully deactivated OpenPGP encryption on this email account",current_user=current_user)
    
@bp.route("/settings/show_alias")
def setings_show_alias():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Show alias error",message="Failed to show alias beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    aliases = db.session.query(Alias).filter(Alias.account_id == current_user.account_id)

    current_app.logger.debug("user " + current_user.user + " account " + current_user.account.account + " show aliases")
    return render_template('settings_show_alias.html',aliases=aliases,current_user=current_user)

@bp.route("/settings/add_alias", methods=['POST', 'GET'])
def settings_add_alias():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Add alias error",message="Failed to add alias beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    form = AliasForm()
    if request.method == 'GET':
        emails = db.session.query(Email).filter(Email.account_id == current_user.account_id)
        account_domains = db.session.query(Account_domain.domain).filter(Account_domain.account_id == current_user.account_id)
        global_domains = db.session.query(Global_domain.domain).filter(Global_domain.is_enabled == True)

        domains = account_domains.union(global_domains)

        return render_template('settings_add_alias.html', form=form, current_user=current_user, emails=emails, domains=domains)

    if request.method == 'POST':
        if not form.validate_on_submit():
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " csrf validation failed")
            return render_template('message.html',headline="Add alias error",message="Failed to add alias, failed csrf validation",current_user=current_user)
        else:
            src_domain_from_form = form.domain.data.strip()
            src_from_form = form.src.data.strip()
            src_email_from_form = src_from_form + "@" + src_domain_from_form
            dst_email_from_form = form.dst.data.strip()

            # Validate src email from form.
            if validators.is_email_allowed(src_email_from_form) == False:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " src email " + src_email_from_form + " validation failed")
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, source email validation failed.",current_user=current_user)

            # Validate dst email from form.
            if validators.is_email_allowed(dst_email_from_form) == False:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " dst email " + dst_email_from_form + " validation failed")
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, destination email validation failed.",current_user=current_user)

            # Validate domain part of src email from form.
            validate_src_email_domain = src_email_from_form.split('@')
            if validators.is_domain_allowed(validate_src_email_domain[1]) == False:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " src email " + src_email_from_form + " domain validation failed")
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, source email domain validation failed.",current_user=current_user)

            # Validate domain part of dst email from form.
            validate_dst_email_domain = dst_email_from_form.split('@')
            if validators.is_domain_allowed(validate_dst_email_domain[1]) == False:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " dst email " + dst_email_from_form + " domain validation failed")
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, destination email validation failed.",current_user=current_user)

            # Check that src email does not already exist in emails table in db.
            is_email_uniq = db.session.query(Email).filter(Email.email == src_email_from_form).count()
            if is_email_uniq != 0:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " src email " + src_email_from_form + " exist in email table in db")
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, source email exist.",current_user=current_user)

            # Check that src email does not already exist in aliases table in db.
            is_alias_uniq = db.session.query(Alias).filter(Alias.src_email == src_email_from_form).count()
            if is_alias_uniq != 0:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " src email " + src_email_from_form + " exist in alias table in db")
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, source email exist.",current_user=current_user)

            # Check that src email domain is owned by account or is global.
            is_src_email_domain_mine = db.session.query(Account_domain).filter(Account_domain.domain == validate_src_email_domain[1], Account_domain.account_id == current_user.account_id).count()
            is_src_email_domain_global = db.session.query(Global_domain).filter(Global_domain.domain == validate_src_email_domain[1]).count()

            if not is_src_email_domain_mine == 1 and not is_src_email_domain_global == 1:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " src email " + src_email_from_form + " domain is not owned by currnet user or not exist in db")
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, source email domain is not allowed.",current_user=current_user)

            # Check that dst email already exist in db and is owned by current user.
            dst_email = db.session.query(Email).filter(Email.email == dst_email_from_form, Email.account_id == current_user.account_id).count()
            if dst_email != 1:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " dst email " + dst_email_from_form + " domain is not owned by currnet user or not exist in db")
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, can not find destination email.",current_user=current_user)
            # Add alias to database.
            dst_email = db.session.query(Email).filter(Email.email == dst_email_from_form, Email.account_id == current_user.account_id).first()
            if is_src_email_domain_mine == 1:
                src_email_domain = db.session.query(Account_domain).filter(Account_domain.domain == validate_src_email_domain[1], Account_domain.account_id == current_user.account_id).first()
                new_alias = Alias(account_id=current_user.account_id, src_email=src_email_from_form, src_account_domain_id=src_email_domain.id, dst_email_id=dst_email.id)
                db.session.add(new_alias)
                db.session.commit()
                current_app.logger.debug("user " + current_user.user + " account " + current_user.account.account + " dst email " + dst_email_from_form + " src email " + src_email_from_form + " added alias")
            elif is_src_email_domain_global == 1:
                src_email_global_domain = db.session.query(Global_domain).filter(Global_domain.domain == validate_src_email_domain[1]).first()
                new_alias = Alias(account_id=current_user.account_id, src_email=src_email_from_form, src_global_domain_id=src_email_global_domain.id, dst_email_id=dst_email.id)
                db.session.add(new_alias)
                db.session.commit()
                current_app.logger.debug("user " + current_user.user + " account " + current_user.account.account + " dst email " + dst_email_from_form + " src email " + src_email_from_form + " added alias")

            return render_template('message.html',headline="Add alias",message="Alias added successfully.",current_user=current_user)

@bp.route("/settings/remove_alias", methods=['POST', 'GET'])
def settings_remove_alias():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Remove Alias Error",message="Failed to remove alias beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        aliases = db.session.query(Alias).filter(Alias.account_id == current_user.account_id)
        return render_template('settings_remove_alias.html',aliases=aliases,current_user=current_user)
    if request.method == 'POST':
        alias_id_from_form = request.form["remove_alias"].strip()

        if alias_id_from_form.isdigit() != True:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " alias id " + str(alias_id_from_form) + " is not a digit")
            return render_template('message.html',headline="Remove Alias Error",message="Failed to remove alias, validation failed.",current_user=current_user)

        # Check alias already exist in db and is owned by current user.
        is_alias_mine = db.session.query(Alias).filter(Alias.id == alias_id_from_form, Alias.account_id == current_user.account_id).count()
        if is_alias_mine != 1:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " alias id " + str(alias_id_from_form) + " is not owned by current use or is not in db")
            return render_template('message.html',headline="Remove Alias Error",message="Failed to remove alias, validation failed.",current_user=current_user)

        # Remove alias from db.
        db.session.query(Alias).filter(Alias.account_id == current_user.account_id, Alias.id == alias_id_from_form).delete()
        db.session.commit()

        current_app.logger.debug("user " + current_user.user + " account " + current_user.account.account + " alias id " + str(alias_id_from_form) + " is removed")
        return render_template('message.html',headline="Remove Alias",message="Successfully removed alias.",current_user=current_user)

@bp.route("/settings/show_domains", methods=['GET'])
def settings_show_domains():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Show domains error",message="Failed to show domains beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    # Get the account domains and global domains.
    account_domains = db.session.query(Account_domain.domain).filter(Account_domain.account_id == current_user.account_id)
    global_domains = db.session.query(Global_domain.domain).filter(Global_domain.is_enabled == True)

    current_app.logger.debug("user " + current_user.user + " account " + current_user.account.account + " show domains")
    return render_template('settings_show_domains.html',account_domains=account_domains,global_domains=global_domains,current_user=current_user)

@bp.route("/settings/add_domain", methods=['POST', 'GET'])
def settings_add_domain():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is authenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Add domain error",message="Failed to add domain beacuse this account is disabled.",current_user=current_user)

    form = DomainForm()
    if request.method == 'GET':
        mx_record_host = current_app.config["MX_RECORD_HOST"]
        mx_record_priority = current_app.config["MX_RECORD_PRIORITY"]
        spf_record = current_app.config["SPF_RECORD"]
        dkim_record = current_app.config["DKIM_RECORD"]
        dmarc_record = current_app.config["DMARC_RECORD"]

        return render_template('settings_add_domain.html', form=form,current_user=current_user,mx_record_host=mx_record_host,mx_record_priority=mx_record_priority,spf_record=spf_record,dkim_record=dkim_record,dmarc_record=dmarc_record)

    if request.method == 'POST':
        if not form.validate_on_submit():
           current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " form validation failed")
           return render_template('message.html',headline="Add Domain Error",message="Failed to add domain, form validation failed.",current_user=current_user)
        else:
            # Validate domain.
            if validators.is_domain_allowed(form.domain.data) == False:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " domain " + form.domain.data + " validation failed")
                return render_template('message.html',headline="Add Domain Error",message="Failed to add domain, domain validation failed.",current_user=current_user)

            # Check that domain do not already exsist.
            does_account_domain_exist = db.session.query(Account_domain).filter(Account_domain.domain == form.domain.data).count()
            does_global_domain_exist = db.session.query(Global_domain).filter(Global_domain.domain == form.domain.data).count()

            if does_account_domain_exist == 1 or does_global_domain_exist == 1:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " domain " + form.domain.data + " already exist in db")
                return render_template('message.html',headline="Add Domain Error",message="Failed to add domain, the current domain already exist.",current_user=current_user)

            # Validate domain dns mx record.
            mx_record_host = current_app.config["MX_RECORD_HOST"]
            mx_record_priority = current_app.config["MX_RECORD_PRIORITY"]
            is_mx = validators.is_mx_valid(str(form.domain.data),mx_record_host,mx_record_priority)
            if is_mx != True:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " domain " + form.domain.data + " mx is not valid")
                return render_template('message.html',headline="Add Domain Error",message="Failed to add domain, the domain dns mx record is not correct.",current_user=current_user)

            # Validate dns spf record.
            spf_record = current_app.config["SPF_RECORD"]
            is_spf = validators.is_spf_valid(form.domain.data,spf_record)
            if is_spf != True:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " domain " + form.domain.data + " spf is not valid")
                return render_template('message.html',headline="Add Domain Error",message="Failed to add domain, the domain dns spf record is not correct.",current_user=current_user)

            # Validate dns dkim record.
            dkim_record = current_app.config["DKIM_RECORD"]
            is_dkim = validators.is_dkim_valid(form.domain.data,dkim_record)
            if is_dkim != True:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " domain " + form.domain.data + " dkim is not valid")
                return render_template('message.html',headline="Add Domain Error",message="Failed to add domain, the domain dns dkim record is not correct.",current_user=current_user)
            
            # Validate dns dmarc record.
            dmarc_record = current_app.config["DMARC_RECORD"]
            is_dmarc = validators.is_dmarc_valid(form.domain.data,dmarc_record)
            if is_dmarc != True:
                current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " domain " + form.domain.data + " dmarc is not valid")
                return render_template('message.html',headline="Add Domain Error",message="Failed to add domain, the domain dns dmarc record is not correct.",current_user=current_user)
            
            # Add domain to db.
            account_domain = Account_domain(account_id=current_user.account_id, domain=form.domain.data)
            db.session.add(account_domain)
            db.session.commit()

            current_app.logger.debug("user " + current_user.user + " account " + current_user.account.account + " domain " + form.domain.data + " was added")
            return render_template('message.html',headline="Add Domain",message="Successfully added domain.",current_user=current_user)

@bp.route("/settings/remove_domain", methods=['POST', 'GET'])
def settings_remove_domain():
    # Check if cookie secret is set.
    if not "secret" in session:
        current_app.logger.warning("secret is not in session")
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        current_app.logger.warning("user is not authenticated")
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        current_app.logger.debug("account " + current_user.account.account + " is not enabled")
        return render_template('message.html',headline="Remove domain error",message="Failed to remove domains beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        domains = db.session.query(Account_domain).filter(Account_domain.account_id == current_user.account_id)
        return render_template('settings_remove_domain.html', domains=domains,current_user=current_user)
    if request.method == 'POST':
        remove_domain_from_form = request.form["remove_domain"].strip()

        # Validate domain.
        if validators.is_domain_allowed(remove_domain_from_form) == False:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " domain " + remove_domain_from_form + " validation failed")
            return render_template('message.html',headline="Remove Domain Error",message="Failed to remove domain, domain backend validation failed.",current_user=current_user)

        # Check if domain exist in db and is owned by current account.
        is_domain_mine = db.session.query(Account_domain).filter(Account_domain.domain == remove_domain_from_form, Account_domain.account_id == current_user.account_id).count()
        if is_domain_mine != 1:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " domain " + remove_domain_from_form + " is not in db or is not owned by current user")
            return render_template('message.html',headline="Remove Domain Error",message="Failed to remove domain, domain does not exist or is not owned by your account.",current_user=current_user)

        domain = db.session.query(Account_domain).filter(Account_domain.domain == remove_domain_from_form).first()

        # Check that domain does not have emails or aliases.
        number_off_emails = db.session.query(Email).filter(Email.account_domain_id == domain.id).count()
        number_off_aliases = db.session.query(Alias).filter(Alias.src_account_domain_id == domain.id).count()

        if number_off_emails != 0 or number_off_aliases != 0:
            current_app.logger.warning("user " + current_user.user + " account " + current_user.account.account + " domain " + remove_domain_from_form + " has email or/and alias")
            return render_template('message.html',headline="Remove Domain Error",message="Failed to remove domain, domain is used in email or alias, remove those first.",current_user=current_user)

        # Remove domain account from db.
        db.session.query(Account_domain).filter(Account_domain.account_id == current_user.account_id, Account_domain.domain == remove_domain_from_form).delete()
        db.session.commit()

        current_app.logger.debug("user " + current_user.user + " account " + current_user.account.account + " domain " + remove_domain_from_form + " removed")
        return render_template('message.html',headline="Remove Domain",message="Successfully removed domain",current_user=current_user)
