# test_jwks_server.py
import unittest
import requests

class TestJWKS_Server(unittest.TestCase):
    def setUp(self):
        self.base_url = 'http://127.0.0.1:8080'

    def test_jwks_endpoint(self):
        response = requests.get(f'{self.base_url}/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        jwks = response.json()
        self.assertTrue('keys' in jwks)
    
    def test_auth_endpoint(self):
        response = requests.post(f'{self.base_url}/auth')
        self.assertEqual(response.status_code, 200)
        token = response.json()['token']
        self.assertTrue(token)

if __name__ == '__main__':
    unittest.main()
