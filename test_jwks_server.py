import pytest
import json
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_jwks_endpoint(client):
    response = client.get('/jwks')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'keys' in data

def test_auth_endpoint(client):
    response = client.post('/auth')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'jwt' in data

def test_expired_auth_endpoint(client):
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'jwt' in data

def test_invalid_route(client):
    response = client.get('/invalid')
    assert response.status_code == 404

def test_invalid_method_jwks_endpoint(client):
    response = client.post('/jwks')
    assert response.status_code == 405

def test_invalid_method_auth_endpoint(client):
    response = client.get('/auth')
    assert response.status_code == 405

if __name__ == '__main__':
    pytest.main()
