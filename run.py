# run.py

from app import create_app

app = create_app()

if __name__ == "__main__":
    PORT = app.config.get('RAVEN_PORT', 8080)
    app.run(host='0.0.0.0', port=PORT)
