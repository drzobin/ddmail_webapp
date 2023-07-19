from flask import Blueprint, session, render_template, request
from argon2 import PasswordHasher
from ddmail.auth import is_athenticated, generate_password, generate_token
from ddmail.models import db, Email, Domain, Alias, Global_domain, User
from ddmail.forms import EmailForm, AliasForm, DomainForm
from ddmail.validators import isEmailAllowed, isDomainAllowed, is_user_allowed

bp = Blueprint("settings", __name__, url_prefix="/")

@bp.route("/settings")
def settings():
    # Check if cookie secret is set.
    if not "secret" in session:
        return render_template('login.html')

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return render_template('login.html')

    return render_template('settings.html', current_user = current_user)

@bp.route("/settings/payment_token", methods=['GET'])
def payment_token():
    # Check if cookie secret is set.
    if not "secret" in session:
        return render_template('login.html')

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return render_template('login.html')

    return render_template('settings_payment_token.html',payment_token = current_user.account.payment_token, current_user = current_user)



@bp.route("/settings/change_password_on_user", methods=['POST', 'GET'])
def settings_change_password_on_user():
    # Check if cookie secret is set.
    if not "secret" in session:
        return render_template('login.html')

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return render_template('login.html')

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
        return render_template('login.html')

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return render_template('login.html')

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
        return render_template('login.html')

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return render_template('login.html')

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
        return render_template('login.html')

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return render_template('login.html')

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Show account users error",message="Failed to show account users beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    users = db.session.query(User).filter(User.account_id == current_user.account_id)

    return render_template('settings_show_account_users.html',users=users, current_user = current_user)

@bp.route("/settings/remove_account_user", methods=['POST', 'GET'])
def settings_remove_account_user():
    # Check if cookie secret is set.
    if not "secret" in session:
        return render_template('login.html')

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return render_template('login.html')

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Remove account user error",message="Failed to remove account user beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        users = db.session.query(User).filter(User.account_id == current_user.account_id)

        return render_template('settings_remove_account_user.html',users=users, current_user=current_user)

    if request.method == 'POST':
        # Check if account is enabled.
        if current_user.account.is_enabled != True:
            return render_template('message.html',headline="Remove email error",message="Failed to remove user beacuse this account is disabled.",current_user=current_user)

        remove_user_from_form = request.form["remove_user"].strip()

        # Validate user data from form.
        if is_user_allowed(remove_user_from_form) == False:
            return render_template('message.html',headline="Remove user error",message="Failed to removed account user, validation failed.",current_user=current_user)

        # Check that user already exist in db and is owned by current account.
        is_user_mine = db.session.query(User).filter(User.user == remove_user_from_form, User.account_id == current_user.account_id).count()
        if is_user_mine != 1:
            return render_template('message.html',headline="Remove user error",message="Failed to removed user, validation failed.",current_user=current_user)

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
        return render_template('login.html')

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return render_template('login.html')

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Add email error",message="Failed to add email beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    form = EmailForm()
    if request.method == 'GET':

        # Get the accounts domains.
        #session.query(SomeModel.col1)
        account_domains = db.session.query(Domain.domain).filter(Domain.account_id == current_user.account_id)
        global_domains = db.session.query(Global_domain.domain).filter(Global_domain.is_enabled == True)

        domains = account_domains.union(global_domains)

        return render_template('settings_add_email.html',form=form, current_user = current_user, domains=domains)

    if request.method == 'POST':
        # Check if org is enabled.
        if current_user.account.is_enabled != True:
            return render_template('message.html',headline="Add email error",message="Failed to add email beacuse this account is disabled.",current_user=current_user)

        if form.validate_on_submit():
            email_from_form = form.email.data.strip()
            domain_from_form = form.domain.data.strip()

            add_email_from_form = email_from_form + "@" + domain_from_form
            #add_email_from_form = form.email.data

            # Validate email from form.
            if isEmailAllowed(add_email_from_form) == False:
                return render_template('message.html',headline="Add email error",message="Failed to add email, email validation failed.",current_user=current_user)

            # Validate domain part of email from form.
            validate_email_domain = add_email_from_form.split('@')
            if isDomainAllowed(validate_email_domain[1]) == False:
                return render_template('message.html',headline="Add email error",message="Failed to add email, domain validation failed.",current_user=current_user)

            # Check if domain is global.
            #isDomainGlobal = isDomainMine = db.session.query(Domain).filter(Domain.domain == validate_email_domain[1], Domain.is_global == True).count()
            isDomainGlobal = db.session.query(Global_domain).filter(Global_domain.domain == validate_email_domain[1], Global_domain.is_enabled == True).count()

            # Check if domain is owned by the org.
            isDomainMine = db.session.query(Domain).filter(Domain.domain == validate_email_domain[1], Domain.account_id == current_user.account_id).count()

            if isDomainMine != 1 and isDomainGlobal != 1:
                return render_template('message.html',headline="Add email error",message="Failed to add email, domain is not owned by you.",current_user=current_user)

            # Check that email does not already exist in emails table in db.
            isEmailUniq = db.session.query(Email).filter(Email.email == add_email_from_form).count()
            if isEmailUniq != 0:
                return render_template('message.html',headline="Add email error",message="Failed to add email, email already exist.",current_user=current_user)

            # Check that email does not already exist in alias table in db.
            isEmailUniq = db.session.query(Alias).filter(Alias.src_email == add_email_from_form).count()
            if isEmailUniq != 0:
                return render_template('message.html',headline="Add email error",message="Failed to add email, email already exist.",current_user=current_user)

            # Generate password.
            cleartext_password = generate_password(24)

            # Hash the password SSHA512.
            #password_hash = createSSHA512(cleartext_password)
            ph = PasswordHasher(time_cost=3,memory_cost=65536,parallelism=1)
            password_hash = ph.hash(cleartext_password)

            # Get the domain id and aff the new email account to db.
            if isDomainMine == 1:
                domain = db.session.query(Domain).filter(Domain.domain == validate_email_domain[1]).first()
                new_email = Email(account_id=int(current_user.account_id), email=add_email_from_form,password_hash=password_hash, domain_id=domain.id)
                db.session.add(new_email)
                db.session.commit()
            elif isDomainGlobal == 1:
                global_domain = db.session.query(Global_domain).filter(Global_domain.domain == validate_email_domain[1]).first()
                new_email = Email(account_id=int(current_user.account_id), email=add_email_from_form,password_hash=password_hash, global_domain_id=global_domain.id)
                db.session.add(new_email)
                db.session.commit()

            return render_template('message.html',headline="Add email",message="Successfully added email: " + add_email_from_form + " with password: " + cleartext_password ,current_user=current_user)
        else:
            return render_template('message.html',headline="Add email error",message="Failed to add email, csrf validation failed.",current_user=current_user)


@bp.route("/settings/show_email")
def settings_show_email():
    # Check if cookie secret is set.
    if not "secret" in session:
        return render_template('login.html')

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return render_template('login.html')

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Show email error",message="Failed to show email beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    emails = db.session.query(Email).filter(Email.account_id == current_user.account_id)

    return render_template('settings_show_email.html',emails=emails, current_user = current_user)

@bp.route("/settings/remove_email", methods=['POST', 'GET'])
def settings_remove_email():
    # Check if cookie secret is set.
    if not "secret" in session:
        return render_template('login.html')

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return render_template('login.html')

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Remove email error",message="Failed to remove email beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        emails = db.session.query(Email).filter(Email.account_id == current_user.account_id)

        return render_template('settings_remove_email.html',emails=emails, current_user=current_user)
    if request.method == 'POST':
        # Check if org is enabled.
        if current_user.account.is_enabled != True:
            return render_template('message.html',headline="Remove email error",message="Failed to remove email beacuse this account is disabled.",current_user=current_user)

        remove_email_from_form = request.form["remove_email"].strip()

        # Validate email from form.
        if isEmailAllowed(remove_email_from_form) == False:
            return render_template('message.html',headline="Remove email error",message="Failed to removed email, validation failed.",current_user=current_user)

        # Validate domain part of email from form.
        validate_email_domain = remove_email_from_form.split('@')
        if isDomainAllowed(validate_email_domain[1]) == False:
            return render_template('message.html',headline="Remove email error",message="Failed to removed email, validation failed.",current_user=current_user)

        # Check that email already exist in db and is owned by current user.
        isEmailMine = db.session.query(Email).filter(Email.email == remove_email_from_form, Email.account_id == current_user.account_id).count()
        if isEmailMine != 1:
            return render_template('message.html',headline="Remove email error",message="Failed to removed email, validation failed.",current_user=current_user)

        # Remove email account from db.
        db.session.query(Email).filter(Email.account_id == current_user.account_id, Email.email == remove_email_from_form).delete()
        db.session.commit()

        return render_template('message.html',headline="Remove email",message="Successfully removed email.",current_user=current_user)

@bp.route("/settings/change_password_on_email", methods=['POST', 'GET'])
def settings_change_password_on_email():
    # Check if cookie secret is set.
    if not "secret" in session:
        return render_template('login.html')

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return render_template('login.html')

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        emails = db.session.query(Email).filter(Email.account_id == current_user.account_id)

        return render_template('settings_change_password_on_email.html',emails=emails, current_user=current_user)

    if request.method == 'POST':
        # Check if org is enabled.
        if current_user.account.is_enabled != True:
            return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account beacuse this account is disabled.",current_user=current_user)

        change_password_on_email_from_form = request.form["change_password_on_email"].strip()

        # Validate email from form.
        if isEmailAllowed(change_password_on_email_from_form) == False:
            return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account, validation failed.",current_user=current_user)

        # Validate domain part of email from form.
        validate_email_domain = change_password_on_email_from_form.split('@')
        if isDomainAllowed(validate_email_domain[1]) == False:
            return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account, validation failed.",current_user=current_user)

        # Check that email already exist in db and is owned by current user.
        isEmailMine = db.session.query(Email).filter(Email.email == change_password_on_email_from_form, Email.account_id == current_user.account_id).count()
        if isEmailMine != 1:
            return render_template('message.html',headline="Change password on email account error",message="Failed to change password on email account, validation failed.",current_user=current_user)

        # Generate password.
        cleartext_password = generate_password(24)
        print("cleartext_password:" + cleartext_password)

        # Hash the password SSHA512.
        #password_hash = createSSHA512(cleartext_password)

        # Hash the password argon2.
        #ph = PasswordHasher()
        ph = PasswordHasher(time_cost=3,memory_cost=65536,parallelism=1)
        password_hash = ph.hash(cleartext_password)
        print("password_hash:" + password_hash)

        # Get the domain id.
        domain = db.session.query(Domain).filter(Domain.domain == validate_email_domain[1]).first()

        # Change password on email account from db.
        #db.session.query(Email).filter(Email.account_id == current_user.account_id, Email.email == change_password_on_email_from_form).update({'password_hash': password_hash})
        email = db.session.query(Email).filter(Email.account_id == current_user.account_id, Email.email == change_password_on_email_from_form).first()
        email.password_hash = password_hash
        db.session.commit()

        return render_template('message.html',headline="Change password on email account",message="Successfully changed password on email account: " + change_password_on_email_from_form + " to new password: " + cleartext_password ,current_user=current_user)

@bp.route("/settings/show_alias")
def setings_show_alias():
    # Check if cookie secret is set.
    if not "secret" in session:
        return render_template('login.html')

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return render_template('login.html')

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Show alias error",message="Failed to show alias beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    aliases = db.session.query(Alias).filter(Alias.account_id == current_user.account_id)

    return render_template('settings_show_alias.html',aliases=aliases,current_user=current_user)

@bp.route("/settings/add_alias", methods=['POST', 'GET'])
def settings_add_alias():
    # Check if cookie secret is set.
    if not "secret" in session:
        return render_template('login.html')

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return render_template('login.html')

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Add alias error",message="Failed to add alias beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    form = AliasForm()
    if request.method == 'GET':
        emails = db.session.query(Email).filter(Email.account_id == current_user.account_id)
        account_domains = db.session.query(Domain.domain).filter(Domain.account_id == current_user.account_id)
        global_domains = db.session.query(Global_domain.domain).filter(Global_domain.is_enabled == True)

        domains = account_domains.union(global_domains)

        return render_template('settings_add_alias.html', form=form, current_user=current_user, emails=emails, domains=domains)
    if request.method == 'POST':
        # Check if account is enabled.
        if current_user.account.is_enabled != True:
            return render_template('message.html',headline="Add alias error",message="Failed to add alias beacuse this account is disabled.",current_user=current_user)

        if form.validate_on_submit():
            src_domain_from_form = form.domain.data.strip()
            src_from_form = form.src.data.strip()
            src_email_from_form = src_from_form + "@" + src_domain_from_form
            dst_email_from_form = form.dst.data.strip()

            # Validate src email from form.
            if isEmailAllowed(src_email_from_form) == False:
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, source email validation failed.",current_user=current_user)

            # Validate dst email from form.
            if isEmailAllowed(dst_email_from_form) == False:
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, destination email validation failed.",current_user=current_user)

            # Validate domain part of src email from form.
            validate_src_email_domain = src_email_from_form.split('@')
            if isDomainAllowed(validate_src_email_domain[1]) == False:
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, source email domain validation failed.",current_user=current_user)

            # Validate domain part of dst email from form.
            validate_dst_email_domain = dst_email_from_form.split('@')
            if isDomainAllowed(validate_dst_email_domain[1]) == False:
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, destination email validation failed.",current_user=current_user)

            # Check that src email does not already exist in emails table in db.
            isEmailUniq = db.session.query(Email).filter(Email.email == src_email_from_form).count()
            if isEmailUniq != 0:
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, source email exist.",current_user=current_user)

            # Check that src email does not already exist in aliases table in db.
            isAliasUniq = db.session.query(Alias).filter(Alias.src_email == src_email_from_form).count()
            if isAliasUniq != 0:
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, source email exist.",current_user=current_user)

            # Check that src email domain is owned by account or is global.
            is_src_email_domain_mine = db.session.query(Domain).filter(Domain.domain == validate_src_email_domain[1], Domain.account_id == current_user.account_id).count()
            is_src_email_domain_global = db.session.query(Global_domain).filter(Global_domain.domain == validate_src_email_domain[1]).count()

            if not is_src_email_domain_mine == 1 and not is_src_email_domain_global == 1:
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, source email domain is not allowed.",current_user=current_user)

            # Check that dst email already exist in db and is owned by current user.
            dst_email = db.session.query(Email).filter(Email.email == dst_email_from_form, Email.account_id == current_user.account_id).first()
            if not dst_email.email:
                return render_template('message.html',headline="Add alias error",message="Failed to add alias, can not find destination email.",current_user=current_user)
            # Add alias to database.
            if is_src_email_domain_mine == 1:
                src_email_domain = db.session.query(Domain).filter(Domain.domain == validate_src_email_domain[1], Domain.account_id == current_user.account_id).first()
                new_alias = Alias(account_id=current_user.account_id, src_email=src_email_from_form, src_domain_id=src_email_domain.id, dst_email_id=dst_email.id)
                db.session.add(new_alias)
                db.session.commit()
            elif is_src_email_domain_global == 1:
                src_email_global_domain = db.session.query(Global_domain).filter(Global_domain.domain == validate_src_email_domain[1]).first()
                new_alias = Alias(account_id=current_user.account_id, src_email=src_email_from_form, src_global_domain_id=src_email_global_domain.id, dst_email_id=dst_email.id)
                db.session.add(new_alias)
                db.session.commit()

            return render_template('message.html',headline="Add alias",message="Alias added successfully.",current_user=current_user)
        else:
            return render_template('message.html',headline="Add alias error",message="Failed to add alias, failed csrf validation",current_user=current_user)

@bp.route("/settings/remove_alias", methods=['POST', 'GET'])
def settings_remove_alias():
    # Check if cookie secret is set.
    if not "secret" in session:
        return render_template('login.html')

    # Check if user is athenticated
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return render_template('login.html')

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Remove alias error",message="Failed to remove alias beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        aliases = db.session.query(Alias).filter(Alias.account_id == current_user.account_id)
        return render_template('settings_remove_alias.html',aliases=aliases,current_user=current_user)
    if request.method == 'POST':
        # Check if org is enabled.
        if current_user.account.is_enabled != True:
            return render_template('message.html',headline="Remove alias error",message="Failed to remove alias beacuse this account is disabled.",current_user=current_user)

        alias_id_from_form = request.form["remove_alias"].strip()

        if alias_id_from_form.isdigit() != True:
            return render_template('message.html',headline="Remove alias error",message="Failed to remove alias, validation failed.",current_user=current_user)

        # Check alias already exist in db and is owned by current user.
        isAliasMine = db.session.query(Alias).filter(Alias.id == alias_id_from_form, Alias.account_id == current_user.account_id).count()
        if isAliasMine != 1:
            return render_template('message.html',headline="Remove alias error",message="Failed to remove alias, validation failed.",current_user=current_user)

        # Remove alias from db.
        db.session.query(Alias).filter(Alias.account_id == current_user.account_id, Alias.id == alias_id_from_form).delete()
        db.session.commit()

        return render_template('message.html',headline="Remove alias",message="Successfully removed alias.",current_user=current_user)

@bp.route("/settings/show_domains", methods=['GET'])
def settings_show_domains():
    # Check if cookie secret is set.
    if not "secret" in session:
        return render_template('login.html')

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return render_template('login.html')

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Show domains error",message="Failed to show domains beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    # Get the account domains and global domains.
    account_domains = db.session.query(Domain.domain).filter(Domain.account_id == current_user.account_id)
    global_domains = db.session.query(Global_domain.domain).filter(Global_domain.is_enabled == True)

    domains = account_domains.union(global_domains)

    return render_template('settings_show_domains.html',domains=domains,current_user=current_user)

@bp.route("/settings/add_domain", methods=['POST', 'GET'])
def settings_add_domain():
    # Check if cookie secret is set.
    if not "secret" in session:
        return render_template('login.html')

    # Check if user is authenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return render_template('login.html')

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Add domain error",message="Failed to add domain beacuse this account is disabled.",current_user=current_user)

    form = DomainForm()
    if request.method == 'GET':
        return render_template('settings_add_domain.html', form=form,current_user=current_user)
    if request.method == 'POST':
        if form.validate_on_submit():

            # Validate domain some more.
            if isDomainAllowed(form.domain.data) == False:
                return render_template('message.html',headline="Add domain error",message="Failed to add domain, domain validation failed.",current_user=current_user)

            # Check that domain do not already exsist.
            does_domain_exist = db.session.query(Domain).filter(Domain.domain == form.domain.data).count()
            does_global_domain_exist = db.session.query(Global_domain).filter(Global_domain.domain == form.domain.data).count()

            if not does_domain_exist == 1 or not does_global_domain_exist == 1:
                return render_template('message.html',headline="Add domain error",message="Failed to add domain, the current domain already exist.",current_user=current_user)

            # Add domain to db.
            domain = Domain(account_id=current_user.account_id, domain=form.domain.data)
            db.session.add(domain)
            db.session.commit()

            return render_template('message.html',headline="Add domain",message="Successfully added domain.",current_user=current_user)
        else:
            return render_template('message.html',headline="Add domain error",message="Failed to add domain.",current_user=current_user)


@bp.route("/settings/remove_domain", methods=['POST', 'GET'])
def settings_remove_domain():
    # Check if cookie secret is set.
    if not "secret" in session:
        return render_template('login.html')

    # Check if user is athenticated.
    current_user = is_athenticated(session["secret"])

    # If user is not athenticated send them to the login page.
    if current_user == None:
        return render_template('login.html')

    # Check if account is enabled.
    if current_user.account.is_enabled != True:
        return render_template('message.html',headline="Remove domain error",message="Failed to remove domains beacuse this account is disabled. In order to enable the account you need to pay, see payments option in menu.",current_user=current_user)

    if request.method == 'GET':
        domains = db.session.query(Domain).filter(Domain.account_id == current_user.account_id)
        return render_template('settings_remove_domain.html', domains=domains,current_user=current_user)
    if request.method == 'POST':
        # Check if org is enabled.
        if current_user.account.is_enabled != True:
            return render_template('message.html',headline="Remove domain error",message="Failed to remove domain beacuse this account is disabled.",current_user=current_user)

        remove_domain_from_form = request.form["remove_domain"].strip()

        # Validate domain.
        if isDomainAllowed(remove_domain_from_form) == False:
            return render_template('message.html',headline="Remove domain error",message="Failed to remove domain, domain validation failed.",current_user=current_user)

        # Check domain already exist in db and is owned by current user.
        isDomainMine = db.session.query(Domain).filter(Domain.domain == remove_domain_from_form, Domain.account_id == current_user.account_id).count()
        if isDomainMine != 1:
            return render_template('message.html',headline="Remove domain error",message="Filed to remove domain",current_user=current_user)

        domain = db.session.query(Domain).filter(Domain.domain == remove_domain_from_form).first()

        # Check that domain does not have emails or aliases.
        numberOfEmails = db.session.query(Email).filter(Email.domain_id == domain.id).count()

        numberOfAliases = db.session.query(Alias).filter(Alias.src_domain_id == domain.id).count()

        if numberOfEmails != 0 or numberOfAliases != 0:
            return render_template('message.html',headline="Remove domain error",message="Failed to remove domain, domain is used in email or alias, remove those first.",current_user=current_user)


        # Remove domain account from db.
        db.session.query(Domain).filter(Domain.account_id == current_user.account_id, Domain.domain == remove_domain_from_form).delete()
        db.session.commit()

        return render_template('message.html',headline="Remove domain",message="Successfully removed domain",current_user=current_user)


