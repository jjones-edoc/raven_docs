# app/routes/main.py

from .auth import login_required
from flask import Blueprint, render_template, redirect, url_for, request, session, current_app
from functools import wraps
import jwt
import logging

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    return redirect(url_for('main.landing'))


@main_bp.route('/landing')
@login_required
def landing(user):
    return render_template('landing.html', user=user)


@main_bp.route('/set_session')
def set_session_route():
    session['test'] = 'Session is working!'
    return "Session set!"


@main_bp.route('/get_session')
def get_session_route():
    return session.get('test', 'Session not set.')
