class Prod():
    WTF_CSRF_SECRET_KEY = 'changeme'
    SECRET_KEY = 'changeme'
    SERVER_NAME = '172.16.23.137:5000'
    SQLALCHEMY_DATABASE_URI = 'mysql://mail_rw:password@localhost/mail'
    SQLALCHEMY_TRACK_MODIFICATIONS = False 

