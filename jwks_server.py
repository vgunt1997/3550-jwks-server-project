from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import jwt
import datetime

app = Flask(__name__)

# Dictionary to hold generated keys
keys = {}

def generate_key_pair(kid, expiry_days):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    # Serialize public key to PEM format
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    expiry = datetime.datetime.utcnow() + datetime.timedelta(days=expiry_days)
    keys[kid] = {"pem": pem, "expiry": expiry}
    return private_key


@app.route('/jwks', methods=['GET'])
def jwks():
    jwks = {
        "keys": [
            {
                "kid": kid,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": keys[kid]["pem"].split('\n')[1],
                "e": "AQAB"
            }
            for kid in keys if keys[kid]["expiry"] > datetime.datetime.utcnow()
        ]
    }
    return jsonify(jwks)


@app.route('/auth', methods=['POST'])
def authenticate():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"message": "Missing username or password"}), 400

    # Fake user authentication
    username = data['username']
    password = data['password']
    if username == 'fakeuser' and password == 'password':
        # Generate JWT
        private_key = generate_key_pair("fakekid", 30)  # Expire in 30 days
        expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
        payload = {'sub': username, 'exp': expiry}
        token = jwt.encode(payload, private_key, algorithm='RS256')
        return jsonify({"access_token": token.decode('utf-8')})

    return jsonify({"message": "Invalid username or password"}), 401


if __name__ == '__main__':
    app.run(port=8080)
