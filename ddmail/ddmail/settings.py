from flask import Blueprint, session, render_template, request, current_app, redirect, url_for
from argon2 import PasswordHasher
from ddmail.auth import is_athenticated, generate_password, generate_token
from ddmail.models import db, Email, Account_domain, Alias, Global_domain, User
from ddmail.forms import EmailForm, AliasForm, DomainForm, EmailPasswordForm
from ddmail.validators import is_email_allowed, is_domain_allowed, is_username_allowed, is_password_allowed, is_mx_valid, is_spf_valid, is_dkim_valid, is_dmarc_valid
import requests
import base64

bp = Blueprint("settings", __name__, url_prefix="/")

@bp.route("/settings")
def settings():
    # Check if cookie secret is set.
    if not "secret" in session:
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return redirect(url_for('auth.login'))

    return render_template('settings.html', current_user = current_user)

@bp.route("/settings/payment_token", methods=['GET'])
def payment_token():
    # Check if cookie secret is set.
    if not "secret" in session:
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return redirect(url_for('auth.login'))

    return render_template('settings_payment_token.html',payment_token = current_user.account.payment_token, current_user = current_user)

@bp.route("/settings/change_password_on_user", methods=['POST', 'GET'])
def settings_change_password_on_user():
    # Check if cookie secret is set.
    if not "secret" in session:
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
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

        return render_template('message.html',headline="Change password on user",message="Successfully changed password on user: " + current_user.user + " to new password: " + cleartext_password ,current_user=current_user)

@bp.route("/settings/change_key_on_user", methods=['POST', 'GET'])
def settings_change_key_on_user():
    # Check if cookie secret is set.
    if not "secret" in session:
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
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

        return render_template('message.html',headline="Change key on user",message="Successfully changed key on user: " + current_user.user + " to new key: " + cleartext_password_key ,current_user=current_user)


@bp.route("/settings/add_user_to_account", methods=['POST', 'GET'])
def settings_add_user_to_account():
    # Check if cookie secret is set.
    if not "secret" in session:
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
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
        return render_template('settings_added_user_to_account.html',current_user=current_user,account=current_user.account.account,user=user,cleartext_password=cleartext_password,cleartext_password_key=cleartext_password_key)

@bp.route("/settings/show_account_users")
def settings_show_account_users():
    # Check if cookie secret is set.
    if not "secret" in session:
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Show account users error",message="Failed to show account users beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    users = db.session.query(User).filter(User.account_id == current_user.account_id)

    return render_template('settings_show_account_users.html',users=users, current_user = current_user)

@bp.route("/settings/remove_account_user", methods=['POST', 'GET'])
def settings_remove_account_user():
    # Check if cookie secret is set.
    if not "secret" in session:
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Remove account user error",message="Failed to remove account user beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        users = db.session.query(User).filter(User.account_id == current_user.account_id)

        return render_template('settings_remove_account_user.html',users=users, current_user=current_user)

    if request.method == 'POST':
        remove_user_from_form = request.form["remove_user"].strip()

        # Validate user data from form.
        if is_username_allowed(remove_user_from_form) == False:
            return render_template('message.html',headline="Remove user error",message="Failed to removed account user, illigal character in string.",current_user=current_user)

        # Check that user already exist in db and is owned by current account.
        is_user_mine = db.session.query(User).filter(User.user == remove_user_from_form, User.account_id == current_user.account_id).count()
        if is_user_mine != 1:
            return render_template('message.html',headline="Remove user error",message="Failed to removed account user, validation failed.",current_user=current_user)

        # Do not allow to remove current loged in user.
        if remove_user_from_form == current_user.user:
            return render_template('message.html',headline="Remove user error",message="Failed to remove account user, you can not remove the same user as you are logged in as.",current_user=current_user)

        # Remove email account from db.
        db.session.query(User).filter(User.account_id == current_user.account_id, User.user == remove_user_from_form).delete()
        db.session.commit()

        return render_template('message.html',headline="Remove user",message="Successfully removed user.",current_user=current_user)

@bp.route("/settings/add_email", methods=['POST', 'GET'])
def settings_add_email():
    # Check if cookie secret is set.
    if not "secret" in session:
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
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
            return render_template('message.html',headline="Add email error",message="Failed to add email, csrf validation failed.",current_user=current_user)
        else:
            email_from_form = form.email.data.strip()
            domain_from_form = form.domain.data.strip()

            add_email_from_form = email_from_form + "@" + domain_from_form

            # Validate email from form.
            if is_email_allowed(add_email_from_form) == False:
                return render_template('message.html',headline="Add email error",message="Failed to add email, email validation failed.",current_user=current_user)

            # Validate domain part of email from form.
            validate_email_domain = add_email_from_form.split('@')
            if is_domain_allowed(validate_email_domain[1]) == False:
                return render_template('message.html',headline="Add email error",message="Failed to add email, domain validation failed.",current_user=current_user)

            # Check if domain is global.
            is_domain_global = db.session.query(Global_domain).filter(Global_domain.domain == validate_email_domain[1], Global_domain.is_enabled == True).count()

            # Check if domain is owned by the account.
            is_domain_mine = db.session.query(Account_domain).filter(Account_domain.domain == validate_email_domain[1], Account_domain.account_id == current_user.account_id).count()

            if is_domain_mine != 1 and is_domain_global != 1:
                return render_template('message.html',headline="Add email error",message="Failed to add email, domain is not active in our system.",current_user=current_user)

            # Check that email does not already exist in emails table in db.
            is_email_uniq = db.session.query(Email).filter(Email.email == add_email_from_form).count()
            if is_email_uniq != 0:
                return render_template('message.html',headline="Add email error",message="Failed to add email, email already exist.",current_user=current_user)

            # Check that email does not already exist in alias table in db.
            is_email_uniq = db.session.query(Alias).filter(Alias.src_email == add_email_from_form).count()
            if is_email_uniq != 0:
                return render_template('message.html',headline="Add email error",message="Failed to add email, email already exist.",current_user=current_user)

            # Generate password.
            cleartext_password = generate_password(24)

            # Hash the password SSHA512.
            ph = PasswordHasher(time_cost=3,memory_cost=65536,parallelism=1)
            password_hash = ph.hash(cleartext_password)

            # Get the domain id and aff the new email account to db.
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
            r_respone = requests.post(dmcp_keyhandler_url, {"email":add_email_from_form,"key_password":base64.b64encode(bytes(cleartext_password, 'utf-8')),"password":dmcp_keyhandler_password}, timeout=5)
            # Check if password protected encryption key creation was successfull.
            if r_respone.status_code != 200 or r_respone.content != b'done':
                return render_template('message.html',headline="Add email error",message="Failed trying to create password protected encryptions keys.",current_user=current_user)

            return render_template('message.html',headline="Add Email Account",message="Successfully added email: " + add_email_from_form + " with password: " + cleartext_password ,current_user=current_user)

@bp.route("/settings/show_email")
def settings_show_email():
    # Check if cookie secret is set.
    if not "secret" in session:
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Show email error",message="Failed to show email beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    emails = db.session.query(Email).filter(Email.account_id == current_user.account_id)

    return render_template('settings_show_email.html',emails=emails, current_user = current_user)

@bp.route("/settings/remove_email", methods=['POST', 'GET'])
def settings_remove_email():
    # Check if cookie secret is set.
    if not "secret" in session:
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Remove email error",message="Failed to remove email beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        emails = db.session.query(Email).filter(Email.account_id == current_user.account_id)

        return render_template('settings_remove_email.html',emails=emails, current_user=current_user)
    if request.method == 'POST':
        remove_email_from_form = request.form["remove_email"].strip()

        # Validate email from form.
        if is_email_allowed(remove_email_from_form) == False:
            return render_template('message.html',headline="Remove email error",message="Failed to removed email, validation failed.",current_user=current_user)

        # Validate domain part of email from form.
        validate_email_domain = remove_email_from_form.split('@')
        domain = validate_email_domain[1]
        if is_domain_allowed(domain) == False:
            return render_template('message.html',headline="Remove email error",message="Failed to removed email, validation failed.",current_user=current_user)

        # Check that email already exist in db and is owned by current user.
        is_email_mine = db.session.query(Email).filter(Email.email == remove_email_from_form, Email.account_id == current_user.account_id).count()
        if is_email_mine != 1:
            return render_template('message.html',headline="Remove email error",message="Failed to removed email, validation failed.",current_user=current_user)

        # Remove email account from db.
        db.session.query(Email).filter(Email.account_id == current_user.account_id, Email.email == remove_email_from_form).delete()
        db.session.commit()

        # Remove email account data from storage with email_remover.
        email_remover_url = current_app.config["EMAIL_REMOVER_URL"]
        email_remover_password = current_app.config["EMAIL_REMOVER_PASSWORD"]
        r_respone = requests.post(email_remover_url, {"password":email_remover_password,"domain":domain,"email":remove_email_from_form}, timeout=5)

        # Check if removal was successfull.
        if r_respone.status_code != 200 or r_respone.content != b'done':
            return render_template('message.html',headline="Remove email error",message="Failed to remove data on disc for email account.",current_user=current_user)

        return render_template('message.html',headline="Remove Email Account",message="Successfully removed email.",current_user=current_user)

@bp.route("/settings/change_password_on_email", methods=['POST', 'GET'])
def settings_change_password_on_email():
    # Check if cookie secret is set.
    if not "secret" in session:
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
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
        if is_email_allowed(change_password_on_email_from_form) == False:
            return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account, validation failed.",current_user=current_user)

        # Validate domain part of email from form.
        validate_email_domain = change_password_on_email_from_form.split('@')
        if is_domain_allowed(validate_email_domain[1]) == False:
            return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account, validation failed.",current_user=current_user)
        
        # Validate current password from form.
        if is_password_allowed(current_cleartext_password_from_form) == False:
            return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account, validation failed on current password.",current_user=current_user)

        # Check that email already exist in db and is owned by current user.
        is_email_mine = db.session.query(Email).filter(Email.email == change_password_on_email_from_form, Email.account_id == current_user.account_id).count()
        if is_email_mine != 1:
            return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account, validation failed.",current_user=current_user)

        # Get current password hash for email account.
        email_from_db = db.session.query(Email).filter(Email.email == change_password_on_email_from_form, Email.account_id == current_user.account_id).first()

        # Check current password is correct.
        try:
            print(current_cleartext_password_from_form)
            print(email_from_db.password_hash)
            if ph.verify(email_from_db.password_hash, current_cleartext_password_from_form) != True:
                return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account, current email account password is wrong.",current_user=current_user)
        except:
            return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account, current email account password is wrong.",current_user=current_user)

        # Generate password.
        cleartext_password = generate_password(24)

        # Change password on encryption key.
        dmcp_keyhandler_url = current_app.config["DMCP_KEYHANDLER_URL"] + "/change_password_on_key"
        dmcp_keyhandler_password = current_app.config["DMCP_KEYHANDLER_PASSWORD"]
        r_respone = requests.post(dmcp_keyhandler_url, {"email":change_password_on_email_from_form,"current_key_password":base64.b64encode(bytes(current_cleartext_password_from_form, 'utf-8')),"new_key_password":base64.b64encode(bytes(cleartext_password, 'utf-8')),"password":dmcp_keyhandler_password}, timeout=5)
            
        # Check if password on encryption key change was successfull.
        if r_respone.status_code != 200 or r_respone.content != b'done':
            return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account, failed to change password on encryption key.",current_user=current_user)

        # Hash the password argon2.
        ph = PasswordHasher(time_cost=3,memory_cost=65536,parallelism=1)
        password_hash = ph.hash(cleartext_password)

        # Change password on email account from db.
        email = db.session.query(Email).filter(Email.account_id == current_user.account_id, Email.email == change_password_on_email_from_form).first()
        email.password_hash = password_hash
        db.session.commit()

        return render_template('message.html',headline="Change password on Email Account",message="Successfully changed password on email account: " + change_password_on_email_from_form + " to new password: " + cleartext_password ,current_user=current_user)

@bp.route("/settings/show_alias")
def setings_show_alias():
    # Check if cookie secret is set.
    if not "secret" in session:
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Show alias error",message="Failed to show alias beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    aliases = db.session.query(Alias).filter(Alias.account_id == current_user.account_id)

    return render_template('settings_show_alias.html',aliases=aliases,current_user=current_user)

@bp.route("/settings/add_alias", methods=['POST', 'GET'])
def settings_add_alias():
    # Check if cookie secret is set.
    if not "secret" in session:
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
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
            return render_template('message.html',headline="Add alias error",message="Failed to add alias, failed csrf validation",current_user=current_user)
        else:
            src_domain_from_form = form.domain.data.strip()
            src_from_form = form.src.data.strip()
            src_email_from_form = src_from_form + "@" + src_domain_from_form
            dst_email_from_form = form.dst.data.strip()

            # Validate src email from form.
            if is_email_allowed(src_email_from_form) == False:
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, source email validation failed.",current_user=current_user)

            # Validate dst email from form.
            if is_email_allowed(dst_email_from_form) == False:
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, destination email validation failed.",current_user=current_user)

            # Validate domain part of src email from form.
            validate_src_email_domain = src_email_from_form.split('@')
            if is_domain_allowed(validate_src_email_domain[1]) == False:
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, source email domain validation failed.",current_user=current_user)

            # Validate domain part of dst email from form.
            validate_dst_email_domain = dst_email_from_form.split('@')
            if is_domain_allowed(validate_dst_email_domain[1]) == False:
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, destination email validation failed.",current_user=current_user)

            # Check that src email does not already exist in emails table in db.
            is_email_uniq = db.session.query(Email).filter(Email.email == src_email_from_form).count()
            if is_email_uniq != 0:
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, source email exist.",current_user=current_user)

            # Check that src email does not already exist in aliases table in db.
            is_alias_uniq = db.session.query(Alias).filter(Alias.src_email == src_email_from_form).count()
            if is_alias_uniq != 0:
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, source email exist.",current_user=current_user)

            # Check that src email domain is owned by account or is global.
            is_src_email_domain_mine = db.session.query(Account_domain).filter(Account_domain.domain == validate_src_email_domain[1], Account_domain.account_id == current_user.account_id).count()
            is_src_email_domain_global = db.session.query(Global_domain).filter(Global_domain.domain == validate_src_email_domain[1]).count()

            if not is_src_email_domain_mine == 1 and not is_src_email_domain_global == 1:
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, source email domain is not allowed.",current_user=current_user)

            # Check that dst email already exist in db and is owned by current user.
            dst_email = db.session.query(Email).filter(Email.email == dst_email_from_form, Email.account_id == current_user.account_id).count()
            if dst_email != 1:
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, can not find destination email.",current_user=current_user)
            # Add alias to database.
            dst_email = db.session.query(Email).filter(Email.email == dst_email_from_form, Email.account_id == current_user.account_id).first()
            if is_src_email_domain_mine == 1:
                src_email_domain = db.session.query(Account_domain).filter(Account_domain.domain == validate_src_email_domain[1], Account_domain.account_id == current_user.account_id).first()
                new_alias = Alias(account_id=current_user.account_id, src_email=src_email_from_form, src_account_domain_id=src_email_domain.id, dst_email_id=dst_email.id)
                db.session.add(new_alias)
                db.session.commit()
            elif is_src_email_domain_global == 1:
                src_email_global_domain = db.session.query(Global_domain).filter(Global_domain.domain == validate_src_email_domain[1]).first()
                new_alias = Alias(account_id=current_user.account_id, src_email=src_email_from_form, src_global_domain_id=src_email_global_domain.id, dst_email_id=dst_email.id)
                db.session.add(new_alias)
                db.session.commit()

            return render_template('message.html',headline="Add alias",message="Alias added successfully.",current_user=current_user)

@bp.route("/settings/remove_alias", methods=['POST', 'GET'])
def settings_remove_alias():
    # Check if cookie secret is set.
    if not "secret" in session:
        return redirect(url_for('auth.login'))

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Remove Alias Error",message="Failed to remove alias beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        aliases = db.session.query(Alias).filter(Alias.account_id == current_user.account_id)
        return render_template('settings_remove_alias.html',aliases=aliases,current_user=current_user)
    if request.method == 'POST':
        alias_id_from_form = request.form["remove_alias"].strip()

        if alias_id_from_form.isdigit() != True:
            return render_template('message.html',headline="Remove Alias Error",message="Failed to remove alias, validation failed.",current_user=current_user)

        # Check alias already exist in db and is owned by current user.
        is_alias_mine = db.session.query(Alias).filter(Alias.id == alias_id_from_form, Alias.account_id == current_user.account_id).count()
        if is_alias_mine != 1:
            return render_template('message.html',headline="Remove Alias Error",message="Failed to remove alias, validation failed.",current_user=current_user)

        # Remove alias from db.
        db.session.query(Alias).filter(Alias.account_id == current_user.account_id, Alias.id == alias_id_from_form).delete()
        db.session.commit()

        return render_template('message.html',headline="Remove Alias",message="Successfully removed alias.",current_user=current_user)

@bp.route("/settings/show_domains", methods=['GET'])
def settings_show_domains():
    # Check if cookie secret is set.
    if not "secret" in session:
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Show domains error",message="Failed to show domains beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    # Get the account domains and global domains.
    account_domains = db.session.query(Account_domain.domain).filter(Account_domain.account_id == current_user.account_id)
    global_domains = db.session.query(Global_domain.domain).filter(Global_domain.is_enabled == True)

    domains = account_domains.union(global_domains)

    return render_template('settings_show_domains.html',domains=domains,current_user=current_user)

@bp.route("/settings/add_domain", methods=['POST', 'GET'])
def settings_add_domain():
    # Check if cookie secret is set.
    if not "secret" in session:
        return redirect(url_for('auth.login'))

    # Check if user is authenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
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
           return render_template('message.html',headline="Add Domain Error",message="Failed to add domain, form validation failed.",current_user=current_user)
        else:
            # Validate domain.
            if is_domain_allowed(form.domain.data) == False:
                return render_template('message.html',headline="Add Domain Error",message="Failed to add domain, domain validation failed.",current_user=current_user)

            # Check that domain do not already exsist.
            does_account_domain_exist = db.session.query(Account_domain).filter(Account_domain.domain == form.domain.data).count()
            does_global_domain_exist = db.session.query(Global_domain).filter(Global_domain.domain == form.domain.data).count()

            if does_account_domain_exist == 1 or does_global_domain_exist == 1:
                return render_template('message.html',headline="Add Domain Error",message="Failed to add domain, the current domain already exist.",current_user=current_user)

            # Validate domain dns mx record.
            mx_record_host = current_app.config["MX_RECORD_HOST"]
            mx_record_priority = current_app.config["MX_RECORD_PRIORITY"]
            is_mx = is_mx_valid(str(form.domain.data),mx_record_host,mx_record_priority)
            if is_mx != True:
                return render_template('message.html',headline="Add Domain Error",message="Failed to add domain, the domain dns mx record is not correct.",current_user=current_user)

            # Validate dns spf record.
            spf_record = current_app.config["SPF_RECORD"]
            is_spf = is_spf_valid(form.domain.data,spf_record)
            if is_spf != True:
                return render_template('message.html',headline="Add Domain Error",message="Failed to add domain, the domain dns spf record is not correct.",current_user=current_user)

            # Validate dns dkim record.
            dkim_record = current_app.config["DKIM_RECORD"]
            is_dkim = is_dkim_valid(form.domain.data,dkim_record)
            if is_dkim != True:
                return render_template('message.html',headline="Add Domain Error",message="Failed to add domain, the domain dns dkim record is not correct.",current_user=current_user)
            
            # Validate dns dmarc record.
            dmarc_record = current_app.config["DMARC_RECORD"]
            is_dmarc = is_dmarc_valid(form.domain.data,dmarc_record)
            if is_dmarc != True:
                return render_template('message.html',headline="Add Domain Error",message="Failed to add domain, the domain dns dmarc record is not correct.",current_user=current_user)
            
            # Add domain to db.
            account_domain = Account_domain(account_id=current_user.account_id, domain=form.domain.data)
            db.session.add(account_domain)
            db.session.commit()

            return render_template('message.html',headline="Add Domain",message="Successfully added domain.",current_user=current_user)

@bp.route("/settings/remove_domain", methods=['POST', 'GET'])
def settings_remove_domain():
    # Check if cookie secret is set.
    if not "secret" in session:
        return redirect(url_for('auth.login'))

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return redirect(url_for('auth.login'))

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Remove domain error",message="Failed to remove domains beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        domains = db.session.query(Account_domain).filter(Account_domain.account_id == current_user.account_id)
        return render_template('settings_remove_domain.html', domains=domains,current_user=current_user)
    if request.method == 'POST':
        remove_domain_from_form = request.form["remove_domain"].strip()

        # Validate domain.
        if is_domain_allowed(remove_domain_from_form) == False:
            return render_template('message.html',headline="Remove Domain Error",message="Failed to remove domain, domain backend validation failed.",current_user=current_user)

        # Check if domain exist in db and is owned by current account.
        is_domain_mine = db.session.query(Account_domain).filter(Account_domain.domain == remove_domain_from_form, Account_domain.account_id == current_user.account_id).count()
        if is_domain_mine != 1:
            return render_template('message.html',headline="Remove Domain Error",message="Failed to remove domain, domain does not exist or is not owned by your account.",current_user=current_user)

        domain = db.session.query(Account_domain).filter(Account_domain.domain == remove_domain_from_form).first()

        # Check that domain does not have emails or aliases.
        number_off_emails = db.session.query(Email).filter(Email.account_domain_id == domain.id).count()
        number_off_aliases = db.session.query(Alias).filter(Alias.src_account_domain_id == domain.id).count()

        if number_off_emails != 0 or number_off_aliases != 0:
            return render_template('message.html',headline="Remove Domain Error",message="Failed to remove domain, domain is used in email or alias, remove those first.",current_user=current_user)

        # Remove domain account from db.
        db.session.query(Account_domain).filter(Account_domain.account_id == current_user.account_id, Account_domain.domain == remove_domain_from_form).delete()
        db.session.commit()

        return render_template('message.html',headline="Remove Domain",message="Successfully removed domain",current_user=current_user)
