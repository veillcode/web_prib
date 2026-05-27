from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
import json, os, uuid, bcrypt, jwt, re
from datetime import datetime, timedelta, timezone
from functools import wraps
from werkzeug.utils import secure_filename
import requests
import threading, time

# ── Config ────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DATA_FILE   = os.path.join(BASE_DIR, 'data', 'db.json')
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')
PUBLIC_DIR  = os.path.join(BASE_DIR, 'public')
JWT_SECRET  = os.environ.get('JWT_SECRET', 'veilfile_secret_python_2025')
JWT_DAYS    = 7
PORT        = int(os.environ.get('PORT', 5000))
MAX_MB      = 50

os.makedirs(os.path.join(BASE_DIR, 'data'), exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)

app = Flask(__name__, static_folder=PUBLIC_DIR, static_url_path='')
CORS(app)
app.config['MAX_CONTENT_LENGTH'] = MAX_MB * 1024 * 1024

# ── Database ──────────────────────────────────────
def load_db():
    if not os.path.exists(DATA_FILE):
        return {'users': [], 'profiles': [], 'files': [], 'folders': []}
    db = json.load(open(DATA_FILE, 'r'))
    if 'folders' not in db: db['folders'] = []
    return db

def save_db(db):
    with open(DATA_FILE, 'w') as f:
        json.dump(db, f, indent=2)

# ── Auth middleware ───────────────────────────────
def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token tidak ditemukan.'}), 401
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            request.user_id  = payload['userId']
            request.username = payload['username']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token sudah kadaluarsa.'}), 401
        except Exception:
            return jsonify({'error': 'Token tidak valid.'}), 401
        return f(*args, **kwargs)
    return decorated

def make_token(user_id, username):
    exp = datetime.now(timezone.utc) + timedelta(days=JWT_DAYS)
    return jwt.encode({'userId': user_id, 'username': username, 'exp': exp}, JWT_SECRET, algorithm='HS256')

COLORS = ['#a78bfa','#60a5fa','#f472b6','#34d399','#fb923c','#facc15','#e879f9']

# ══════════════════════════════════════════════════
#  STATIC + ERROR HANDLER
# ══════════════════════════════════════════════════
@app.route('/')
def index():
    return send_from_directory(PUBLIC_DIR, 'index.html')

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint tidak ditemukan'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

# ══════════════════════════════════════════════════
#  AUTH
# ══════════════════════════════════════════════════
@app.route('/api/auth/register', methods=['POST'])
def register():
    body = request.get_json() or {}
    username = (body.get('username') or '').strip()
    email = (body.get('email') or '').strip()
    password = body.get('password') or ''

    if not username or not email or not password:
        return jsonify({'error': 'Semua kolom harus diisi.'}), 400
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return jsonify({'error': 'Format email tidak valid.'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password minimal 6 karakter.'}), 400

    db = load_db()
    if any(u['username'].lower() == username.lower() for u in db['users']):
        return jsonify({'error': 'Username sudah digunakan.'}), 409
    if any(u['email'].lower() == email.lower() for u in db['users']):
        return jsonify({'error': 'Email sudah terdaftar.'}), 409

    import random
    user_id = 'user_' + uuid.uuid4().hex[:12]
    now = datetime.now(timezone.utc).isoformat()
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    db['users'].append({'id': user_id, 'username': username, 'email': email, 'password': hashed, 'createdAt': now})
    db['profiles'].append({'userId': user_id, 'displayName': username, 'bio': '', 'avatarColor': random.choice(COLORS), 'avatarFile': None, 'createdAt': now, 'updatedAt': now})
    save_db(db)
    return jsonify({'message': 'Akun berhasil dibuat!'}), 201

# ... (login, verify, profile, dll tetap sama seperti yang sudah bagus)

# ── SCANNER UPLOAD (SUDAH DIPERBAIKI) ─────────────────────
@app.route('/api/scan/upload', methods=['POST'])
@auth_required
def scan_upload():
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'Tidak ada gambar yang dikirim.'}), 400
        
        file = request.files['image']
        if not file.filename:
            return jsonify({'error': 'File gambar tidak valid.'}), 400

        ext = os.path.splitext(file.filename)[1].lower()
        if ext not in ['.jpg', '.jpeg', '.png', '.webp', '.gif', '.heic']:
            return jsonify({'error': 'Format gambar tidak didukung.'}), 400

        unique_name = uuid.uuid4().hex + ext
        scan_dir = os.path.join(PUBLIC_DIR, 'scans')
        os.makedirs(scan_dir, exist_ok=True)
        
        path = os.path.join(scan_dir, unique_name)
        file.save(path)

        # Auto delete setelah 5 menit
        def delete_later():
            time.sleep(300)
            try:
                if os.path.exists(path):
                    os.remove(path)
            except:
                pass
        threading.Thread(target=delete_later, daemon=True).start()

        host = request.host_url.rstrip('/')
        public_url = f"{host}/scans/{unique_name}"

        return jsonify({'url': public_url, 'success': True})

    except Exception as e:
        print("Scanner Error:", str(e))
        return jsonify({'error': f'Terjadi kesalahan server: {str(e)}'}), 500


# ══════════════════════════════════════════════════
if __name__ == '__main__':
    print(f'\n🚀 Veilfile Python Backend')
    print(f'🌐 http://localhost:{PORT}')
    print(f'📁 Database : {DATA_FILE}')
    print(f'📂 Uploads  : {UPLOADS_DIR}\n')
    app.run(host='0.0.0.0', port=PORT, debug=False)