from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators

# Form modul for domain.
class DomainForm(FlaskForm):
    domain = StringField('Domain', [validators.DataRequired(),validators.Length(min=4, max=200)])

# Form modul for email password.
class EmailPasswordForm(FlaskForm):
    email_password = PasswordField('Email account current password', [validators.DataRequired(),validators.Length(min=24, max=24)])

# Form modul for email.
class EmailForm(FlaskForm):
    email = StringField('Email', [validators.DataRequired(),validators.Length(min=1, max=200)])
    domain = StringField('Domain', [validators.DataRequired(),validators.Length(min=4, max=200)])

# Form modul for alias.
class AliasForm(FlaskForm):
    src = StringField('Source', [validators.DataRequired(),validators.Length(min=1, max=200)])
    domain = StringField('Domain', [validators.DataRequired(),validators.Length(min=4, max=200)])
    dst = StringField('Destination', [validators.DataRequired(),validators.Length(min=4, max=200)])

