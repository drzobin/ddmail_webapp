import os

class Base:
    """Base configuration class."""
    DKIM_RECORD = "\"v=DKIM1; k=rsa;  \\\\009p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoxbFCUM83lUvHKku3mE/IOb2LArgPsjzhijO4pZfVLrLp7dv8RKDs4MmtFHrdWf4UibDFZtPm4IKcagDD3LlqgPSeewnfesI/kGCdz2SqPA/R5Cip5I1swtQ1lKa41eu6Rxym32fzCrRAhBfOZqM05BKPQQpxcSuyNmKOz+HGlGtkUMk5ebhWDtTsoc7ntw\" \"nhnAxaF+T61YQdYyCL \\\\009P7l6KRULaDJ3U7AkNAYrXpv0AdfjDVZp+GXu5fqTFTMi5pYGv1pj4621OSysDmjFlPksCgDouE11N+sJVCVPj//8gJCpzDv7y2kET9MIPmIlKGBTC1AQg5KWrbkeQPcEnzhRwIDAQAB\""
    DMCP_KEYHANDLER_URL = os.environ.get('DMCP_KEYHANDLER_URL', 'http://127.0.0.1:8002')
    DMCP_KEYHANDLER_PASSWORD = 'password'
    DMARC_RECORD = "\"v=DMARC1; p=none\""
    EMAIL_REMOVER_URL = os.environ.get('EMAIL_REMOVER_URL', '127.0.0.1:8001')
    EMAIL_REMOVER_PASSWORD = 'password'
    MX_RECORD_PRIORITY = 10
    MX_RECORD_HOST = 'mail.ddmail.se.'
    OPENPGP_KEYHANDLER_URL = os.environ.get('OPENPGP_KEYHANDLER_URL', 'http://127.0.0.1:8003')
    OPENPGP_KEYHANDLER_PASSWORD = 'password'
    SECRET_KEY = 'password'
    SPF_RECORD = "\"v=spf1 mx -all\""
    SQLALCHEMY_DATABASE_URI = None
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_SECRET_KEY = 'password'


class Prod(Base):
    """Production configuration class."""
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI', 'mysql://mail_rw:password@127.0.0.1/mail')


class Test(Base):
    """Test configuration class."""
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI', 'mysql://mail_test_rw:password@127.0.0.1/mail_test')


class Dev(Base):
    """Development configuration class."""
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI', 'mysql://mail_dev_rw:password@127.0.0.1/mail_dev')
