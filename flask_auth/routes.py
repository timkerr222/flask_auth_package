from flask import Flask, request, jsonify, session
import pyotp
from flask import Blueprint, render_template, redirect, url_for, flash, session
import datetime as datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, validators
import qrcode
from io import BytesIO
import base64
from datetime import timedelta, timezone
from .forms import LoginForm, SignUpForm, OTPVerificationForm
# authentication/routes.py
from . import auth  # Import the Blueprint from your __init__.py
import user_util as u

# Utility Functions
# This is a simple in-memory storage for demo purposes
# For a production application, use a more robust storage solution
temp_storage = {}

def store_temp_user(username, data):
    temp_storage[username] = data

def get_temp_user(username):
    return temp_storage.get(username)

def clear_temp_user(username):
    temp_storage.pop(username, None)

def generate_qr_code_base64(data):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill='black', back_color='white')
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"



@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
   
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        users = u.load_users()
        user = users.get(username)
        if user and u.validate_credentials(username, password):
            session['pending_login_user'] = username  # Store username temporarily
            return redirect(url_for('auth.verify_otp'))
        else:
            flash('Invalid username or password.')

    return render_template('login.html', form=form)


# SIGNUP - STEP 1
@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if u.user_exists(username):
            flash("User already exists!")
            return redirect(url_for('auth.login'))

        otp_provisioning_url, secret_key = u.generate_otp_url(username)

        # Store data in server-side storage
        store_temp_user(username, {'password': password, 'secret_key': secret_key})

        session['temp_username'] = username
        session['otp_provisioning_url'] = otp_provisioning_url

        return redirect(url_for('auth.display_qr'))

    return render_template('signup.html', form=form)



# SIGNUP STEP 2

@auth.route('/display_qr', methods=['GET'])
def display_qr():
    otp_provisioning_url = session.get('otp_provisioning_url')
    if not otp_provisioning_url:
        flash('Something went wrong. Please signup again.')
        return redirect(url_for('auth.signup'))

    form = OTPVerificationForm()
    # Convert image to base64 for HTML display
    qr_code = generate_qr_code_base64(otp_provisioning_url)
    # Render template with the QR code image
    return render_template('display_qr.html', qr_code=qr_code, form=form)

# SIGNUP - STEP 3
@auth.route('/validate_signup_otp', methods=['POST'])
def validate_signup_otp():
    form = OTPVerificationForm()
    if form.validate_on_submit():
        otp = form.otp.data
        username = session.get('temp_username')
        temp_user = get_temp_user(username)

        if temp_user and pyotp.TOTP(temp_user['secret_key']).verify(otp):
            u.add_user(username, temp_user['password'], temp_user['secret_key'])

            # Clear temporary data
            clear_temp_user(username)
            session.pop('temp_username', None)

            return redirect(url_for('auth.login'))
        else:
            # Attach the error directly to the form's field
            form.otp.errors.append('Invalid OTP. Please try again.')

    return render_template('display_qr.html', form=form)


@auth.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    form = OTPVerificationForm()
    if form.validate_on_submit():
        otp = form.otp.data
        username = session.get('pending_login_user')

        if not username:
            return redirect(url_for('auth.login'))

        users = u.load_users()
        user = users.get(username)

        if user and pyotp.TOTP(user['secret_key']).verify(otp):
            session['user'] = username  # Finalize login
            session.pop('pending_login_user', None)  # Clean up
            flash('Login successful.')
            return redirect(url_for('dashboard'))  # Redirect to the home page or dashboard
        else:
            form.otp.errors.append('Invalid OTP.')

    return render_template('verify_otp.html', form=form)


@auth.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))
