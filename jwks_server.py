# jwks_server.py
import os
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from jose import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)

# Generate RSA key pair
def generate_key_pair(kid, expiry_date):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return {
        'kid': kid,
        'expiry': expiry_date,
        'private_key': pem_private,
        'public_key': pem_public
    }

# JWKS endpoint
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    current_time = datetime.utcnow()
    jwks = []
    for key in keys.values():
        if key['expiry'] > current_time:
            jwks.append({
                'kid': key['kid'],
                'kty': 'RSA',
                'alg': 'RS256',
                'use': 'sig',
                'n': key['public_key']
            })
    return jsonify(keys=jwks)

# Authentication endpoint
@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired')
    kid = list(keys.keys())[0] if expired else list(keys.keys())[1]
    private_key = keys[kid]['private_key']
    expiry = keys[kid]['expiry']
    
    token_payload = {
        'sub': 'fakeuser',
        'exp': int((datetime.utcnow() + timedelta(minutes=30)).timestamp()),
        'iat': int(datetime.utcnow().timestamp()),
        'kid': kid
    }

    jwt_token = jwt.encode(token_payload, private_key, algorithm='RS256')
    return jsonify(token=jwt_token)

if __name__ == '__main__':
    keys = {
        'key1': generate_key_pair('key1', datetime.utcnow() + timedelta(hours=1)),
        'key2': generate_key_pair('key2', datetime.utcnow() + timedelta(days=1))
    }
    app.run(port=8080)
