import re


def get_csrf_token(data):
    m = re.search(b'<input type="hidden" name="csrf_token" value="(.*)"', data)
    if m:
        csrf_token = m.group(1).decode("utf-8")
    else:
        csrf_token = None

    return csrf_token


def get_register_data(data):
    """Extract registration data from response.
    
    Handles two formats:
    1. Encrypted file format: Account:...\nUsername:...\nPassword:...\nKey file data:...
    2. HTML format with <p> tags (legacy)
    
    Returns dict with keys: account, username, password, key
    """
    register_data = {}

    # Get account - try both formats
    m = re.search(b"Account:([^\n]+)", data)
    if not m:
        m = re.search(b"<p>Account: (.*)</p>", data)
    if m:
        register_data["account"] = m.group(1).decode("utf-8")
    else:
        raise ValueError("Could not find account in response data")

    # Get username
    m = re.search(b"Username:([^\n]+)", data)
    if not m:
        m = re.search(b"<p>Username: (.*)</p>", data)
    if m:
        register_data["username"] = m.group(1).decode("utf-8")
    else:
        raise ValueError("Could not find username in response data")

    # Get password
    m = re.search(b"Password:([^\n]+)", data)
    if not m:
        m = re.search(b"<p>Password: (.*)</p>", data)
    if m:
        register_data["password"] = m.group(1).decode("utf-8")
    else:
        raise ValueError("Could not find password in response data")

    # Get key
    m = re.search(b"Key file data:([^\n]+)", data)
    if not m:
        m = re.search(b'value="(.*)"', data)
    if m:
        register_data["key"] = m.group(1).decode("utf-8")
    else:
        raise ValueError("Could not find key in response data")

    return register_data
