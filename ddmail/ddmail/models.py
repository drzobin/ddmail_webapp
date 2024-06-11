from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

db = SQLAlchemy()

# DB modul for accounts.
class Account(db.Model):
    __tablename__ = 'accounts'
    id = db.Column(db.Integer, primary_key=True)
    account = db.Column(db.String(100), unique=True, nullable=False)
    payment_token = db.Column(db.String(12), unique=True, nullable=False)
    funds_in_sek = db.Column(db.Integer, nullable=False)
    is_enabled = db.Column(db.Boolean, unique=False, nullable=False)
    is_gratis = db.Column(db.Boolean, unique=False, nullable=False)
    total_storage_space_g = db.Column(db.Integer, nullable=False)
    created = db.Column(db.DateTime, nullable=False)
    last_time_disabled = db.Column(db.DateTime, nullable=True)

    aliases = relationship("Alias", back_populates="account")
    emails = relationship("Email", back_populates="account")
    account_domains = relationship("Account_domain", back_populates="account")
    users = relationship("User", back_populates="account")
    openpgp_public_keys = relationship("Openpgp_public_key", back_populates="account")

# DB modul for aliases.
class Alias(db.Model):
    __tablename__ = 'aliases'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    account_id = db.mapped_column(ForeignKey("accounts.id"), nullable=False)
    src_email = db.Column(db.String(200), unique=True, nullable=False)
    src_account_domain_id = db.mapped_column(db.Integer, ForeignKey('account_domains.id'), nullable=True)
    src_global_domain_id = db.mapped_column(db.Integer, ForeignKey('global_domains.id'), nullable=True)
    dst_email_id = db.mapped_column(db.Integer, ForeignKey('emails.id'), nullable=False)

    account = relationship("Account", back_populates="aliases")
    email = relationship("Email", back_populates="aliases")
    account_domain = relationship("Account_domain", back_populates="aliases")
    global_domain = relationship("Global_domain", back_populates="aliases")

# DB modul for emails.
class Email(db.Model):
    __tablename__ = 'emails'
    id = db.Column(db.Integer, primary_key=True,nullable=False)
    account_id = db.mapped_column(db.Integer, ForeignKey('accounts.id'),nullable=False)
    account_domain_id = db.mapped_column(db.Integer, ForeignKey('account_domains.id'),nullable=True)
    global_domain_id = db.mapped_column(db.Integer, ForeignKey('global_domains.id'),nullable=True)
    openpgp_public_key_id = db.mapped_column(db.Integer, ForeignKey('openpgp_public_keys.id'),nullable=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(2096), nullable=False)
    storage_space_mb = db.Column(db.Integer, nullable=False)

    account = relationship("Account", back_populates="emails")
    account_domain = relationship("Account_domain", back_populates="emails")
    global_domain = relationship("Global_domain", back_populates="emails")
    aliases = relationship("Alias", back_populates="email")
    openpgp_public_key = relationship("Openpgp_public_key", back_populates="emails")

# DB modul for openpgp_public_keys.
class Openpgp_public_key(db.Model):
    __tablename__ = 'openpgp_public_keys'
    id = db.Column(db.Integer, primary_key=True,nullable=False)
    account_id = db.mapped_column(db.Integer, ForeignKey('accounts.id'),nullable=False)
    fingerprint = db.Column(db.String(200), unique=True, nullable=False)

    account = relationship("Account", back_populates="openpgp_public_keys")
    emails = relationship("Email", back_populates="openpgp_public_key")

# DB modul for account domains.
class Account_domain(db.Model):
    __tablename__ = 'account_domains'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    account_id = db.mapped_column(db.Integer, ForeignKey('accounts.id'), nullable=False)
    domain = db.Column(db.String(200), unique=True, nullable=False)

    account = relationship("Account", back_populates="account_domains")
    emails = relationship("Email", back_populates="account_domain")
    aliases = relationship("Alias", back_populates="account_domain")

# DB modul for global domains.
class Global_domain(db.Model):
    __tablename__ = 'global_domains'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    domain = db.Column(db.String(200), unique=True, nullable=False)
    is_enabled = db.Column(db.Boolean, unique=False, nullable=False,default=True)

    emails = relationship("Email", back_populates="global_domain")
    aliases = relationship("Alias", back_populates="global_domain")


# DB modul for users.
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    account_id = db.mapped_column(db.Integer, ForeignKey('accounts.id'), nullable=False)
    user = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), unique=True, nullable=False)
    password_key_hash = db.Column(db.String(200), unique=True, nullable=False)

    account = relationship("Account", back_populates="users")
    authenticated = relationship("Authenticated", back_populates="user")

# DB model for authenticated.
class Authenticated(db.Model):
    __tablename__ = 'authenticateds'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    cookie = db.Column(db.String(12), unique=True, nullable=False)
    user_id = db.mapped_column(db.Integer, ForeignKey('users.id'), nullable=False)
    valid_to = db.Column(db.DateTime, nullable=False)

    user = relationship("User", back_populates="authenticated")

    def __init__(self,cookie,user_id,valid_to):
        self.cookie = cookie
        self.user_id = user_id
        self.valid_to = valid_to

