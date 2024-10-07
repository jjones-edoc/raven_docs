# app/routes/auth.py

import os
import jwt
import datetime
import logging
from functools import wraps
from flask import (
    Blueprint, redirect, url_for, session, request,
    render_template, make_response, current_app
)
import requests

auth_bp = Blueprint('auth', __name__)

REDIRECT_URI = "http://localhost:5000/auth/callback"

AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
USER_INFO_ENDPOINT = "https://www.googleapis.com/oauth2/v1/userinfo"


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            logging.debug("No token found in cookies.")
            return redirect(url_for('auth.login'))
        try:
            JWT_SECRET_KEY = current_app.config['JWT_SECRET_KEY']
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
            logging.debug(f"JWT payload: {payload}")
            return f(payload, *args, **kwargs)
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
            logging.debug(f"JWT decode error: {e}")
            return redirect(url_for('auth.login'))
    return decorated_function


@auth_bp.route('/login')
def login():
    state = os.urandom(16).hex()
    session['state'] = state
    logging.debug(f"Generated state: {state}")

    GOOGLE_CLIENT_ID = current_app.config['GOOGLE_CLIENT_ID']

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


@auth_bp.route('/auth/callback')
def callback():
    code = request.args.get('code')
    state = request.args.get('state')

    logging.debug(f"Received state: {state}")
    logging.debug(f"Session state: {session.get('state')}")

    if state != session.get('state'):
        logging.warning("State mismatch. Potential CSRF attack.")
        return "State mismatch. Potential CSRF attack.", 400

    GOOGLE_CLIENT_ID = current_app.config['GOOGLE_CLIENT_ID']
    GOOGLE_CLIENT_SECRET = current_app.config['GOOGLE_CLIENT_SECRET']

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

    user_info_response = requests.get(USER_INFO_ENDPOINT, params={
        'access_token': access_token
    })
    user_info = user_info_response.json()
    logging.debug(f"User info: {user_info}")

    JWT_SECRET_KEY = current_app.config['JWT_SECRET_KEY']
    payload = {
        'sub': user_info['id'],
        'name': user_info['name'],
        'email': user_info['email'],
        'picture': user_info.get('picture'),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')
    logging.debug(f"Generated JWT: {token}")

    response = make_response(redirect(url_for('main.landing')))
    response.set_cookie('token', token, httponly=True,
                        secure=False, samesite='Lax')
    return response


@auth_bp.route('/logout')
def logout():
    response = make_response(redirect(url_for('auth.login')))
    response.set_cookie('token', '', expires=0)
    return response
