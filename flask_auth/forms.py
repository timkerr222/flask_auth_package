from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, validators


class LoginForm(FlaskForm):
    username = StringField('username', [validators.DataRequired()])
    password = PasswordField('password', [validators.DataRequired()])
    submit = SubmitField('Sign In')

class SignUpForm(FlaskForm):
    username = StringField('username', [validators.DataRequired()])
    password = PasswordField('password', [
        validators.DataRequired(), 
        validators.Length(min=8), 
        validators.Regexp(r'.*\d.*', message="Password must include numbers"),
        validators.Regexp(r'.*[A-Z].*', message="Password must include uppercase letters"),
        validators.Regexp(r'.*[a-z].*', message="Password must include lowercase letters")
    ])
    submit = SubmitField('Get Started')

class OTPVerificationForm(FlaskForm):
    otp = StringField('OTP', [validators.DataRequired()])
    submit = SubmitField('Verify OTP')