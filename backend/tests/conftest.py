import pytest
from backend.app import create_app


class UnavailableCapture:
    """Never open a real network socket in the Phase 2 regression tests."""
    def run(self, *_):
        raise ImportError('test capture dependency is unavailable')


@pytest.fixture
def app():
    application = create_app({'TESTING': True, 'CAPTURE_ENGINE_FACTORY': UnavailableCapture})
    yield application
    application.extensions['monitor'].stop()


@pytest.fixture
def client(app):
    return app.test_client()
