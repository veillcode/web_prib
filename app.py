from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
import json, os, uuid, bcrypt, jwt, re
from datetime import datetime, timedelta, timezone
from functools import wraps
import requests
import threading, time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, 'data', 'db.json')
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')
PUBLIC_DIR = os.path.join(BASE_DIR, 'public')

JWT_SECRET = os.environ.get('JWT_SECRET', 'veilfile_secret_python_2025')
PORT = int(os.environ.get('PORT', 5000))

os.makedirs(os.path.join(BASE_DIR, 'data'), exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)

app = Flask(__name__, static_folder=PUBLIC_DIR, static_url_path='')
CORS(app)

def load_db():
    if not os.path.exists(DATA_FILE):
        return {'users': [], 'profiles': [], 'files': [], 'folders': []}
    db = json.load(open(DATA_FILE, 'r'))
    if 'folders' not in db: db['folders'] = []
    return db

def save_db(db):
    with open(DATA_FILE, 'w') as f:
        json.dump(db, f, indent=2)

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token tidak ditemukan.'}), 401
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            request.user_id = payload['userId']
        except:
            return jsonify({'error': 'Token tidak valid.'}), 401
        return f(*args, **kwargs)
    return decorated

# SCANNER ENDPOINT
@app.route('/api/scan/upload', methods=['POST'])
@auth_required
def scan_upload():
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'Tidak ada gambar.'}), 400
        
        file = request.files['image']
        if not file.filename:
            return jsonify({'error': 'File gambar tidak valid.'}), 400

        ext = os.path.splitext(file.filename)[1].lower()
        if ext not in ['.jpg', '.jpeg', '.png', '.webp', '.gif']:
            return jsonify({'error': 'Format tidak didukung.'}), 400

        unique_name = uuid.uuid4().hex + ext
        scan_dir = os.path.join(PUBLIC_DIR, 'scans')
        os.makedirs(scan_dir, exist_ok=True)
        
        path = os.path.join(scan_dir, unique_name)
        file.save(path)

        def delete_later():
            time.sleep(300)
            try:
                if os.path.exists(path):
                    os.remove(path)
            except:
                pass
        threading.Thread(target=delete_later, daemon=True).start()

        host = request.host_url.rstrip('/')
        return jsonify({'url': f"{host}/scans/{unique_name}"})

    except Exception as e:
        print("Scanner Error:", str(e))
        return jsonify({'error': str(e)}), 500

@app.route('/')
def index():
    return send_from_directory(PUBLIC_DIR, 'index.html')

if __name__ == '__main__':
    print("🚀 Veilfile Backend Started")
    app.run(host='0.0.0.0', port=PORT, debug=False)