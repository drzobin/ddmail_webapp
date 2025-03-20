import re
import dns.resolver

# Validate username. Only allow the following chars: A-Z and 0-9
def is_username_allowed(username):
    pattern = re.compile(r"[A-Z0-9]")

    for char in username:
        if not re.match(pattern, char):
            return False

    return True

# Validate password. Only allow the following chars: A-Z, a-z and 0-9
def is_password_allowed(password):
    pattern = re.compile(r"[a-zA-Z0-9]")

    for char in password:
        if not re.match(pattern, char):
            return False

    return True

# Validate domain names. Only allow the following chars: a-z, 0-9 and .-
def is_domain_allowed(domain):
    if not len(domain) > 3:
        return False

    if domain.startswith('.') or domain.startswith('-'):
        return False
    if domain.endswith('.') or domain.endswith('-'):
        return False
    if '--' in domain:
        return False
    if '..' in domain:
        return False

    if domain.find(".") == -1:
        return False

    pattern = re.compile(r"[a-z0-9.-]")
    for char in domain:
        if not re.match(pattern, char):
            return False

    return True

# Validate email address. Only allow the following chars: a-z, 0-9 and @.-
def is_email_allowed(email):
    if not len(email) > 6:
        return False

    if email.count('@') != 1:
        return False
    if email.startswith('.') or email.startswith('@') or email.startswith('-'):
        return False
    if email.endswith('.') or email.endswith('@') or email.endswith('-'):
        return False

    if '--' in email:
        return False
    if '..' in email:
        return False

    splitted_email = email.split('@')
    if splitted_email[0].startswith('.') or splitted_email[0].startswith('-'):
        return False
    if splitted_email[1].startswith('.') or splitted_email[1].startswith('-'):
        return False

    if splitted_email[0].endswith('.') or splitted_email[0].endswith('-'):
        return False
    if splitted_email[1].endswith('.') or splitted_email[1].endswith('-'):
        return False

    pattern = re.compile(r"[a-z0-9@.-]")
    for char in email:
        if not re.match(pattern, char):
            return False

    return True

# Validate dns domain mx record
def is_mx_valid(domain,host,priority):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        if len(answers) == 1 and str(answers[0].exchange) == host and str(answers[0].preference == priority):
            return True
        else:
            return False
    except:
        return False

# Validate dns spf (as txt) record
def is_spf_valid(domain,spf_record):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if 'spf1' in str(rdata) and str(rdata) == spf_record:
                return True
            else:
                return False
    except:
        return False

# Validate dns dkim (as txt) record
def is_dkim_valid(domain,dkim_record):
    try:
        answers = dns.resolver.resolve("mail._domainkey." + domain, 'TXT')
        for rdata in answers:
            if 'DKIM1' in str(rdata) and str(rdata) == dkim_record:
                return True
            else:
                return False
    except:
        return False
            
# Validate dns dmarc (as txt) record
def is_dmarc_valid(domain,dmarc_record):
    try:
        answers = dns.resolver.resolve("_dmarc." + domain, 'TXT')
        for rdata in answers:
            if 'DMARC1' in str(rdata) and str(rdata) == dmarc_record:
                return True
            else:
                return False
    except:
        return False

# Validate openpgp public key. Only allow the following chars: A-Z, a-z, 0-9 and +/=
def is_openpgp_public_key_allowed(public_key):
    if public_key == None:
        return False

    # Check start and end of string.
    if public_key.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----") != True:
        return False
    if public_key.endswith("-----END PGP PUBLIC KEY BLOCK-----") != True:
        return False

    public_key = public_key.replace("-----BEGIN PGP PUBLIC KEY BLOCK-----","", 1)
    public_key = public_key.replace("-----END PGP PUBLIC KEY BLOCK-----","", 1)

    # Only allow A-Z ,a-z, 0-9 and +/=
    pattern = re.compile(r"[a-zA-Z0-9\+\/\=\s]")
    for char in public_key:
        if not re.match(pattern, char):
            return False

    return True

# Validate openpgp public key fingerprint string. Only allow the following chars: A-Z, 0-9
def is_openpgp_key_fingerprint_allowed(fingerprint):
    if fingerprint == None:
        return False

    # Fingerprint string should be 40 char.
    allowed_len = 40
    if len(fingerprint) != allowed_len:
        return False

    # Only allow A-Z, 0-9
    pattern = re.compile(r"[A-Z0-9]")
    for char in fingerprint:
        if not re.match(pattern, char):
            return False

    return True
