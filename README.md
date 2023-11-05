# FlaskAuth2FA Package

This package provides a Flask extension for handling user authentication.

## Installation

To install FlaskAuth2FA, run:

```
pip install FlaskAuth2FA
```

## Usage

To use FlaskAuth2FA in your Flask application, register the authentication Blueprint:

```python
from flask_auth import auth_blueprint

app.register_blueprint(auth_blueprint, url_prefix='/auth')
```

See the documentation for more details.
