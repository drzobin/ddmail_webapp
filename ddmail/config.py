class Prod():
    WTF_CSRF_SECRET_KEY = 'password'
    SECRET_KEY = 'password'
    SQLALCHEMY_DATABASE_URI = 'mysql://mail_rw:password@localhost/mail'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    EMAIL_REMOVER_URL = '127.0.0.1:8001'
    EMAIL_REMOVER_PASSWORD = 'password'
    DMCP_KEYHANDLER_URL = 'http://127.0.0.1:8001'
    DMCP_KEYHANDLER_PASSWORD = 'password'

class Test():
    WTF_CSRF_SECRET_KEY = 'password'
    SECRET_KEY = 'password'
    SQLALCHEMY_DATABASE_URI = 'mysql://mail_test_rw:password@localhost/mail_test'
    SQLALCHEMY_TRACK_MODIFICATIONS = False 
    EMAIL_REMOVER_URL = '127.0.0.1:8001'
    EMAIL_REMOVER_PASSWORD = 'password'
    DMCP_KEYHANDLER_URL = 'http://127.0.0.1:8001'
    DMCP_KEYHANDLER_PASSWORD = 'password'

class Dev():
    WTF_CSRF_SECRET_KEY = 'password'
    SECRET_KEY = 'password'
    SQLALCHEMY_DATABASE_URI = 'mysql://mail_dev_rw:password@localhost/mail_dev'
    SQLALCHEMY_TRACK_MODIFICATIONS = False 
    EMAIL_REMOVER_URL = '127.0.0.1:8001'
    EMAIL_REMOVER_PASSWORD = 'password'
    DMCP_KEYHANDLER_URL = 'http://127.0.0.1:8001'
    DMCP_KEYHANDLER_PASSWORD = 'password'
