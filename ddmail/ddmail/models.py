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
    assets_in_sek = db.Column(db.Integer)
    is_enabled = db.Column(db.Boolean, unique=False, nullable=False)
    is_gratis = db.Column(db.Boolean, unique=False, nullable=False)
    aliases = relationship("Alias")
    emails = relationship("Email")
    domains = relationship("Domain")
    users = relationship("User")

# DB modul for aliases.
class Alias(db.Model):
    __tablename__ = 'aliases'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    account_id = db.Column(db.Integer, ForeignKey('accounts.id'), nullable=False)
    src_email = db.Column(db.String(200), unique=True, nullable=False)
    src_domain_id = db.Column(db.Integer, ForeignKey('domains.id'), nullable=False)
    dst_email_id = db.Column(db.Integer, ForeignKey('emails.id'), nullable=False)
    account = relationship("Account")
    email = relationship("Email")
    domain = relationship("Domain")

# DB modul for emails.
class Email(db.Model):
    __tablename__ = 'emails'
    id = db.Column(db.Integer, primary_key=True,nullable=False)
    account_id = db.Column(db.Integer, ForeignKey('accounts.id'),nullable=False)
    domain_id = db.Column(db.Integer, ForeignKey('domains.id'),nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(2096), nullable=False)
    account = relationship("Account", back_populates="emails")
    domain = relationship("Domain", back_populates="emails")
    aliases = relationship("Alias")

# DB modul for domains.
class Domain(db.Model):
    __tablename__ = 'domains'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    account_id = db.Column(db.Integer, ForeignKey('accounts.id'), nullable=False)
    domain = db.Column(db.String(200), unique=True, nullable=False)
    is_global = db.Column(db.Boolean, unique=False, nullable=False,default=False)
    account = relationship("Account", back_populates="domains")
    emails = relationship("Email")
    aliases = relationship("Alias")

# DB modul for users.
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    account_id = db.Column(db.Integer, ForeignKey('accounts.id'), nullable=False)
    user = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), unique=True, nullable=False)
    password_key_hash = db.Column(db.String(200), unique=True, nullable=False)
    account = relationship("Account", back_populates="users")
    authenticated = relationship("Authenticated")

# DB model for authenticated.
class Authenticated(db.Model):
    __tablename__ = 'authenticateds'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    cookie = db.Column(db.String(12), unique=True, nullable=False)
    user_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False)
    valid_to = db.Column(db.DateTime, nullable=False)
    user = relationship("User")

    def __init__(self,cookie,user_id,valid_to):
        self.cookie = cookie
        self.user_id = user_id
        self.valid_to = valid_to

