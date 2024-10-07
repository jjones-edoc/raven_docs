import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your_jwt_secret_key")
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
    GOOGLE_PROJECT_ID = os.getenv("GOOGLE_PROJECT_ID")
    GOOGLE_AUTH_URI = os.getenv("GOOGLE_AUTH_URI")
    GOOGLE_TOKEN_URI = os.getenv("GOOGLE_TOKEN_URI")
    GOOGLE_AUTH_PROVIDER_X509_CERT_URL = os.getenv(
        "GOOGLE_AUTH_PROVIDER_X509_CERT_URL")
    GOOGLE_REDIRECT_URI_1 = os.getenv("GOOGLE_REDIRECT_URI_1")
