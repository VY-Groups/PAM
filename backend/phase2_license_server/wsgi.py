"""
WSGI entrypoint for production servers.

    waitress-serve --host 127.0.0.1 --port 5000 wsgi:app
    gunicorn 'wsgi:create_app'          # factory form
    flask --app app run                 # development only
"""
from app import create_app

app = create_app()

__all__ = ["app", "create_app"]
