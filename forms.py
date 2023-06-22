from flask_wtf import FlaskForm
from wtforms import SubmitField, StringField, PasswordField, StringField, PasswordField, validators
from wtforms.validators import InputRequired, Length, Email

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=1, max=50, message='Username must be atleast 1 and atmost 50 characters')])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

class SignUpForm(FlaskForm):
    username = StringField('Username', [validators.InputRequired(), validators.Length(min=1, max=50, message='Username must be atleast 1 and atmost 50 characters')])
    email = StringField('Email Address', [validators.InputRequired(), validators.Email(message='Invalid Email')])
    password = PasswordField('New Password', [
        validators.InputRequired(),
        validators.EqualTo('confirm', message='Passwords must match'),
        validators.Length(min=8, message='Password minimum length of 8')
    ])
    confirm = PasswordField('Repeat Password', [validators.InputRequired()])
    submit = SubmitField('Sign-Up')

class ForgetPassForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email')])
    submit = SubmitField('Reset Password')

class ResetPassForm(FlaskForm):
    password = PasswordField('New Password', [
        validators.InputRequired(),
        validators.EqualTo('confirm', message='Passwords must match'),
        validators.Length(min=8, message='Password minimum length of 8')
    ])
    confirm = PasswordField('Repeat Password', [validators.InputRequired()])
    submit = SubmitField('Reset Password')

class CheckoutForm(FlaskForm):
    submit = SubmitField('Checkout')

class ChangePassForm(FlaskForm):
    current_password = PasswordField('Current Password', [validators.InputRequired()])
    password = PasswordField('New Password', [
        validators.InputRequired(),
        validators.EqualTo('confirm', message='Passwords must match'),
        validators.Length(min=8, message='Password minimum length of 8')
    ])
    confirm = PasswordField('Confirm Password', [validators.InputRequired()])
    submit = SubmitField('Save')