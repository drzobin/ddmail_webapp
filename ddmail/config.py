class Prod():
    WTF_CSRF_SECRET_KEY = 'changeme'
    SECRET_KEY = 'changeme'
    SERVER_NAME = 'www.ddmail.se'
    SQLALCHEMY_DATABASE_URI = 'mysql://mail_rw:password@localhost/mail'
    SQLALCHEMY_TRACK_MODIFICATIONS = False 

