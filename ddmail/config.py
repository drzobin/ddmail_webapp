class Prod():
    WTF_CSRF_SECRET_KEY = 'password'
    SECRET_KEY = 'password'
    SQLALCHEMY_DATABASE_URI = 'mysql://mail_rw:password@localhost/mail'
    SQLALCHEMY_TRACK_MODIFICATIONS = False 

class Test():
    WTF_CSRF_SECRET_KEY = 'password'
    SECRET_KEY = 'password'
    SQLALCHEMY_DATABASE_URI = 'mysql://mail_test_rw:password@localhost/mail_test'
    SQLALCHEMY_TRACK_MODIFICATIONS = False 

class Dev():
    WTF_CSRF_SECRET_KEY = 'password'
    SECRET_KEY = 'password'
    SQLALCHEMY_DATABASE_URI = 'mysql://mail_dev_rw:password@localhost/mail_dev'
    SQLALCHEMY_TRACK_MODIFICATIONS = False 
