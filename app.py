from flask import Flask, jsonify, request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

app = Flask(__name__)

keys = {}

def generate_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return {
        'kid': str(hash(public_key)),
        'expiry': (datetime.datetime.utcnow() + datetime.timedelta(days=30)).isoformat(),
        'public_key': public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    }

@app.route('/jwks', methods=['GET'])
def jwks():
    valid_keys = {kid: key for kid, key in keys.items() if datetime.datetime.utcnow() < datetime.datetime.fromisoformat(key['expiry'])}
    return jsonify({'keys': list(valid_keys.values())})

@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired')
    if expired:
        key = list(keys.values())[0]  # Assume there's only one key for simplicity
    else:
        key = [key for key in keys.values() if datetime.datetime.utcnow() < datetime.datetime.fromisoformat(key['expiry'])][0]
    # Here you would perform user authentication and generate a JWT using the selected key
    jwt = generate_jwt(key)
    return jsonify({'jwt': jwt})

def generate_jwt(key):
    # Implement JWT generation logic here
    return 'JWT'

if __name__ == '__main__':
    keys['key1'] = generate_key()  # Assume there's only one key for simplicity
    app.run(port=8080)
