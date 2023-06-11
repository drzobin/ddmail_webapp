import re

# Validate username and password.
def isUserPassAllowed(userPass):
    pattern = re.compile(r"[a-zA-Z0-9]")

    for char in userPass:
        if not re.match(pattern, char):
            return False

    return True

# Validate domain names.
def isDomainAllowed(domain):
    if domain.startswith('.') or domain.startswith('-'):
        return False
    if domain.endswith('.') or domain.endswith('-'):
        return False

    if domain.find(".") == -1:
        return False

    pattern = re.compile(r"[a-z0-9.-]")
    for char in domain:
        if not re.match(pattern, char):
            return False

    return True

# Validate email address.
def isEmailAllowed(email):
    if email.count('@') != 1:
        return False
    if email.startswith('.') or email.startswith('@') or email.startswith('-'):
        return False
    if email.endswith('.') or email.endswith('@') or email.endswith('-'):
        return False

    splitted_email = email.split('@')
    if splitted_email[0].startswith('.') or splitted_email[0].startswith('-'):
        return False
    if splitted_email[0].endswith('.') or splitted_email[0].endswith('-'):
        return False

    pattern = re.compile(r"[a-z0-9@.-]")
    for char in email:
        if not re.match(pattern, char):
            return False

    return True

# Validate account user.
def is_user_allowed(user):
    pattern = re.compile(r"[A-Z0-9]")

    for char in user:
        if not re.match(pattern, char):
            return False

    return True
