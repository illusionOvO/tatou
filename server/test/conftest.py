import pytest
from server import app as flask_app


@pytest.fixture
def app():
    """Provide Flask app for tests"""
    flask_app.config.update({
        "TESTING": True
    })
    return flask_app


@pytest.fixture
def client(app):
    """Provide Flask test client"""
    return app.test_client()
