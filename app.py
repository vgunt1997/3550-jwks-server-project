from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1, PKCS1v15
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from datetime import datetime
import sqlite3
import uuid
import argon2

# A lot of imports

app = Flask(__name__)

encryption_key = b'YOUR_AES_ENCRYPTION_KEY_HERE'

argon2_params = {
    'time_cost': 2,
    'memory_cost': 102400,
    'parallelism': 2,
    'hash_len': 32,
    'salt_len': 16,
    'encoding': 'utf-8'
}

def initialize_db():
    # Create/open a SQLite DB file
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    
    # Create table for private keys if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    
    # Create table for users if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP      
        )
    ''')
    
    # Create table for authentication logs if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,  
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    ''')
    
    conn.commit()
    conn.close()

def encrypt_data(data):
    # Encrypt data using AES encryption
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(b'\x00' * 16), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_data(encrypted_data):
    # Decrypt data using AES decryption
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(b'\x00' * 16), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_data) + unpadder.finalize()

def save_key_to_db(key, expiry):
    # Serialize key to PEM format
    pem_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Encrypt key
    encrypted_key = encrypt_data(pem_key)

    # Save encrypted key to database
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO keys (key, exp) VALUES (?, ?)
    ''', (encrypted_key, expiry))
    conn.commit()
    conn.close()

def register_user(username, email):
    # Generate secure password using UUIDv4
    password = str(uuid.uuid4())

    # Hash password using Argon2
    hasher = argon2.PasswordHasher(**argon2_params)
    password_hash = hasher.hash(password)

    # Save user details to database
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)
    ''', (username, password_hash, email))
    conn.commit()
    conn.close()

    return password

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')

    if not username or not email:
        return jsonify({'message': 'Username and email are required'}), 400

    try:
        password = register_user(username, email)
        return jsonify({'password': password}), 201
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/auth', methods=['POST'])
def authenticate():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    # Log authentication request
    request_ip = request.remote_addr
    user_id = get_user_id(username)
    log_authentication(request_ip, user_id)

    # Validate user credentials
    if not validate_user(username, password):
        return jsonify({'message': 'Invalid username or password'}), 401

    # Retrieve valid key from database
    key_data = get_valid_key_from_db()

    if key_data:
        # Decrypt key
        decrypted_key = decrypt_data(key_data[0])

        # Deserialize key
        private_key = serialization.load_pem_private_key(decrypted_key, password=None, backend=default_backend())

        # Generate JWT
        token = jwt.encode({'username': username}, private_key, algorithm='RS256')

        return jsonify({'token': token.decode('utf-8')})

    return jsonify({'message': 'No valid key found'}), 401

def log_authentication(request_ip, user_id):
    # Log authentication request
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)
    ''', (request_ip, user_id))
    conn.commit()
    conn.close()

def get_user_id(username):
    # Retrieve user ID by username
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id FROM users WHERE username = ?
    ''', (username,))
    user_id = cursor.fetchone()
    conn.close()

    return user_id[0] if user_id else None

def validate_user(username, password):
    # Validate user credentials
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT password_hash FROM users WHERE username = ?
    ''', (username,))
    user_data = cursor.fetchone()
    conn.close()

    if user_data:
        hasher = argon2.PasswordHasher(**argon2_params)
        try:
            hasher.verify(user_data[0], password)
            return True
        except:
            pass
    return False

if __name__ == '__main__':
    initialize_db()
    app.run(port=8080)
