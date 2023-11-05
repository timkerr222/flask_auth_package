import json
from passlib.hash import bcrypt
import pyotp 
from flask import session

USER_FILE = 'users.json'

def load_users():
    try:
        with open(USER_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_users(users):
    with open(USER_FILE, 'w') as file:
        json.dump(users, file, indent=4)

def add_user(username, password, secret_key):
    users = load_users()

    if username in users:
        raise ValueError("User already exists")

    hashed_password = bcrypt.hash(password)

    # Add new user with secret_key and validated status
    users[username] = {
        'password': hashed_password,
        'secret_key': secret_key,
        'validated': True  # Set to True as user is added post-OTP validation
    }

    save_users(users)


def generate_otp_url(username):
    # Generate a secret key for TOTP
    secret_key = pyotp.random_base32()

    # Create a URL for the QR code
    otp_provisioning_url = pyotp.totp.TOTP(secret_key).provisioning_uri(
        name=username, issuer_name="RxTrail AI"
    )

    return otp_provisioning_url, secret_key


def user_exists(username):
    users = load_users()
    return username in users

def load_user(username):
    users = load_users()
    if username not in users:
        raise ValueError("User does not exist")
  
    return users[username]

def validate_credentials(username, password):
    users = load_users()
    user = users.get(username)

    if not user:
        return False  # User does not exist

    # Check the password
    # 1234567tT#
    print(bcrypt.verify(password, user['password']))
    print(password)
    print(user['password'])
    return bcrypt.verify(password, user['password'])

def update_user(username, update_info):
    users = load_users()
    
    if username not in users:
        raise ValueError("User does not exist")

    users[username].update(update_info)
    save_users(users)

def read_users_from_file():
    with open('users.json', 'r') as file:
        return json.load(file)

def write_users_to_file(users):
    with open('users.json', 'w') as file:
        json.dump(users, file, indent=4)

def delete_user(username):
    users = read_users_from_file()
    users.pop(username, None)
    write_users_to_file(users)

def mark_user_as_invalid(username):
    users = read_users_from_file()
    if username in users:
        users[username]['validated'] = False
    write_users_to_file(users)

# Utility function (can be used in the backend)
def is_logged_in():
    return 'user' in session