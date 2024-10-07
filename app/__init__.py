# app/__init__.py

from flask import Flask
from config import Config
import logging


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize logging
    logging.basicConfig(level=logging.DEBUG)

    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.main import main_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    return app
