import re

def get_csrf_token(data):
    m = re.search(b'<input type="hidden" name="csrf_token" value="(.*)"/>', data)
    csrf_token = m.group(1).decode("utf-8")

    return csrf_token

def get_register_data(data):
    register_data = {}

    # Get account
    m = re.search(b'<p>Account: (.*)</p>', data)
    register_data["account"] = m.group(1).decode("utf-8")
    
    # Get username
    m = re.search(b'<p>Username: (.*)</p>', data)
    register_data["username"] = m.group(1).decode("utf-8")
   
   #Get password
    m = re.search(b'<p>Password: (.*)</p>', data)
    register_data["password"] = m.group(1).decode("utf-8")
    
    #Get key
    m = re.search(b'<p>Key file content: (.*)</p>', data)
    register_data["key"] = m.group(1).decode("utf-8")

    return register_data


