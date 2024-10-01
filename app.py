import os
import json
import jwt
import datetime
import logging
from functools import wraps
from flask import Flask, redirect, url_for, session, request, jsonify, render_template, make_response
from dotenv import load_dotenv
import requests

# Setup logging
logging.basicConfig(level=logging.DEBUG)

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
REDIRECT_URI = "http://localhost:5000/auth/callback"

# OAuth2 endpoints
AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
USER_INFO_ENDPOINT = "https://www.googleapis.com/oauth2/v1/userinfo"


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            logging.debug("No token found in cookies.")
            return redirect(url_for('login'))
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
            # Optionally, you can verify more claims here
            logging.debug(f"JWT payload: {payload}")
            return f(payload, *args, **kwargs)
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
            logging.debug(f"JWT decode error: {e}")
            return redirect(url_for('login'))
    return decorated_function


@app.route('/')
def index():
    return redirect(url_for('landing'))


@app.route('/login')
def login():
    # Generate a state token to prevent request forgery.
    # Store it in the session for later validation.
    state = os.urandom(16).hex()
    session['state'] = state
    logging.debug(f"Generated state: {state}")
    # Prepare the authorization URL
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'response_type': 'code',
        'scope': 'openid email profile',
        'redirect_uri': REDIRECT_URI,
        'state': state,
        'access_type': 'offline',
        'prompt': 'consent'
    }
    auth_url = requests.Request(
        'GET', AUTHORIZATION_ENDPOINT, params=params).prepare().url
    logging.debug(f"Authorization URL: {auth_url}")
    return render_template('login.html', auth_url=auth_url)


@app.route('/auth/callback')
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get('code')
    state = request.args.get('state')

    logging.debug(f"Received state: {state}")
    logging.debug(f"Session state: {session.get('state')}")

    # Validate state token
    if state != session.get('state'):
        logging.warning("State mismatch. Potential CSRF attack.")
        return "State mismatch. Potential CSRF attack.", 400

    # Exchange authorization code for access token
    data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code'
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    token_response = requests.post(TOKEN_ENDPOINT, data=data, headers=headers)
    token_response_data = token_response.json()
    logging.debug(f"Token response: {token_response_data}")

    access_token = token_response_data.get('access_token')
    if not access_token:
        logging.error("Failed to obtain access token.")
        return "Failed to obtain access token.", 400

    # Get user info
    user_info_response = requests.get(USER_INFO_ENDPOINT, params={
                                      'access_token': access_token})
    user_info = user_info_response.json()
    logging.debug(f"User info: {user_info}")

    # Create JWT
    payload = {
        'sub': user_info['id'],
        'name': user_info['name'],
        'email': user_info['email'],
        'picture': user_info.get('picture'),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')
    logging.debug(f"Generated JWT: {token}")

    # Set JWT in a secure cookie
    response = make_response(redirect(url_for('landing')))
    # Set 'secure=True' in production
    response.set_cookie('token', token, httponly=True,
                        secure=False, samesite='Lax')
    return response


@app.route('/landing')
@login_required
def landing(user):
    return render_template('landing.html', user=user)


@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('login')))
    response.set_cookie('token', '', expires=0)
    return response

# Debugging Routes


@app.route('/set_session')
def set_session():
    session['test'] = 'Session is working!'
    return "Session set!"


@app.route('/get_session')
def get_session():
    return session.get('test', 'Session not set.')


if __name__ == '__main__':
    app.run(debug=True)
