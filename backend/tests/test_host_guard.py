"""Local transport security; all databases are in memory."""
import pytest
from backend.app import create_app


@pytest.mark.parametrize('host', ['attacker.invalid:5001', 'localhost.evil', '127.0.0.1.evil'])
@pytest.mark.parametrize('path', ['/api/health', '/socket.io/?EIO=4&transport=polling'])
def test_rebinding_rejected(host, path):
    app = create_app({'TESTING': True})
    response = app.test_client().get(path, headers={'Host': host})
    assert response.status_code == 400
    assert response.json['error']['code'] == 'untrusted_host'
    assert response.headers['Cache-Control'] == 'no-store'


@pytest.mark.parametrize('host', ['localhost:5001', '127.0.0.1:5001', '[::1]:5001'])
def test_loopback_allowed(host):
    app = create_app({'TESTING': True})
    assert app.test_client().get('/api/health', headers={'Host': host}).status_code == 200
