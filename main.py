import json
import random
import string
import uuid
from base64 import b64decode
from datetime import timedelta
from os import getenv

import redis
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dotenv import load_dotenv
from flask import Flask, request, jsonify, abort, render_template

load_dotenv()

app = Flask(__name__)
r = redis.Redis(
    host=getenv('REDIS_HOST', 'localhost'),
    port=int(getenv('REDIS_PORT', '6379')),
    db=int(getenv('REDIS_DB', '0'))
)


def generate_random_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))


def decrypt_symmetric_key(private_key, encrypted_symmetric_key):
    encrypted_key_bytes = b64decode(encrypted_symmetric_key)
    symmetric_key = private_key.decrypt(
        encrypted_key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return symmetric_key


def decrypt_content(content, iv, symmetric_key):
    encrypted_content = b64decode(content)

    tag = encrypted_content[-16:]
    encrypted_content = encrypted_content[:-16]

    cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()

    decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()
    return decrypted_content.decode('utf-8')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/<uuid:record_id>')
def get_record_page(record_id):
    return render_template('record.html', record_id=record_id)


@app.route('/generate_keys', methods=['GET'])
def generate_keys():
    # Генерация приватного и публичного ключей
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Сериализация ключей
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    key_id = str(uuid.uuid4())
    r.setex(f"private_key:{key_id}", timedelta(weeks=2), private_key_pem)

    return jsonify({"key_id": key_id, "public_key": public_key_pem.decode('utf-8')})


@app.route('/save_record', methods=['POST'])
def save_record():
    data = request.json
    encrypted_symmetric_key = data['encrypted_symmetric_key']
    iv = data['iv']
    encrypted_text = data['encrypted_content']
    public_key_id = data['key_id']
    expiry_option = data['expiry_option']

    # Определяем время жизни записи
    if expiry_option == '1_hour':
        expiry = timedelta(hours=1)
    elif expiry_option == '1_day':
        expiry = timedelta(days=1)
    elif expiry_option == '1_week':
        expiry = timedelta(weeks=1)
    else:
        return jsonify({"error": "Invalid expiry option"}), 400

    record_id = str(uuid.uuid4())
    password = generate_random_password()

    r.setex(f"record:{record_id}", expiry, json.dumps({"iv": iv, "content": encrypted_text}))
    r.setex(f"symmetric_key:{record_id}", expiry, encrypted_symmetric_key)
    r.setex(f"password:{record_id}", expiry, password)
    r.setex(f"record_private_key:{record_id}", expiry, public_key_id)

    return jsonify({"record_id": record_id, "password": password})


@app.route('/get_record_info/<uuid:record_id>', methods=['GET'])
def get_record_info(record_id):
    record = r.get(f"record:{record_id}")

    if record:
        ttl = r.ttl(f"record:{record_id}")
        return jsonify({"record_id": str(record_id), "ttl": ttl})
    else:
        abort(404)


@app.route('/get_decrypted_record', methods=['POST'])
def get_decrypted_record():
    data = request.json
    record_id = data['record_id']
    password = data['password']

    saved_password = r.get(f"password:{record_id}")
    if not saved_password or saved_password.decode('utf-8') != password:
        return jsonify({"error": "Invalid password"}), 403

    content = r.get(f"record:{record_id}")
    if not content:
        abort(404)

    key_id = r.get(f"record_private_key:{record_id}")
    if not key_id:
        abort(404)

    private_key_pem = r.get(f"private_key:{key_id.decode()}")
    if not private_key_pem:
        abort(404)

    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )

    symmetric_key = r.get(f"symmetric_key:{record_id}")
    decrypted_symmetric_key = private_key.decrypt(
        b64decode(symmetric_key),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    content_json = json.loads(content)
    decrypted_text = decrypt_content(content_json.get("content"), b64decode(content_json.get("iv")), decrypted_symmetric_key)

    return jsonify({
        "decrypted_text": decrypted_text,
        "ttl": r.ttl(f"record:{record_id}")
    })


if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=getenv('APP_ENV', 'dev') != 'prod', port=int(getenv('APP_PORT', '8080')))
