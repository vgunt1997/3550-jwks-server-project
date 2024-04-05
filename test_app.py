import pytest
import json
from app import app, initialize_db

@pytest.fixture
def client():
    initialize_db()  # Ensure the database is initialized before each test
    with app.test_client() as client:
        yield client

def test_register(client):
    # Test user registration endpoint
    response = client.post('/register', json={'username': 'testuser', 'email': 'test@example.com'})
    assert response.status_code == 201
    data = json.loads(response.data)
    assert 'password' in data

def test_auth_valid_credentials(client):
    # Test authentication with valid credentials
    response = client.post('/auth', json={'username': 'testuser', 'password': 'testpassword'})
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'token' in data

def test_auth_invalid_credentials(client):
    # Test authentication with invalid credentials
    response = client.post('/auth', json={'username': 'testuser', 'password': 'wrongpassword'})
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'message' in data

def test_auth_missing_credentials(client):
    # Test authentication with missing credentials
    response = client.post('/auth', json={})
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'message' in data

def test_jwks_endpoint(client):
    # Test JWKS endpoint
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'keys' in data
    assert len(data['keys']) > 0

if __name__ == "__main__":
    pytest.main()
