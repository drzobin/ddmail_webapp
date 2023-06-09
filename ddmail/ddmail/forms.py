from flask_wtf import FlaskForm
from wtforms import StringField, validators

# Form modul for domain.
class DomainForm(FlaskForm):
    domain = StringField('Domain', [validators.DataRequired(),validators.Length(min=4, max=200)])

# Form modul for email.
class EmailForm(FlaskForm):
    email = StringField('Email', [validators.DataRequired(),validators.Length(min=1, max=200)])
    domain = StringField('Domain', [validators.DataRequired(),validators.Length(min=4, max=200)])

# Form modul for alias.
class AliasForm(FlaskForm):
    src = StringField('Source', [validators.DataRequired(),validators.Length(min=1, max=200)])
    domain = StringField('Domain', [validators.DataRequired(),validators.Length(min=4, max=200)])
    dst = StringField('Destination', [validators.DataRequired(),validators.Length(min=4, max=200)])

