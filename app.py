from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
import json, os, uuid, bcrypt, jwt, re, mimetypes
from datetime import datetime, timedelta, timezone
from functools import wraps
from werkzeug.utils import secure_filename
import requests
import threading, time

# ── CONFIG ────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DATA_FILE   = os.path.join(BASE_DIR, 'data', 'db.json')
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')
PUBLIC_DIR  = os.path.join(BASE_DIR, 'public')
JWT_SECRET  = os.environ.get('JWT_SECRET', 'veilfile_secret_python_2025')
PORT        = int(os.environ.get('PORT', 5000))

os.makedirs(os.path.join(BASE_DIR, 'data'), exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(PUBLIC_DIR, exist_ok=True)
os.makedirs(os.path.join(PUBLIC_DIR, 'scans'), exist_ok=True)
os.makedirs(os.path.join(PUBLIC_DIR, 'avatars'), exist_ok=True)

app = Flask(__name__, static_folder=PUBLIC_DIR, static_url_path='')
CORS(app)

# ── DB HELPERS ────────────────────────────────────────────────────────────────
def load_db():
    if not os.path.exists(DATA_FILE):
        return {'users': [], 'profiles': [], 'files': [], 'folders': []}
    with open(DATA_FILE, 'r') as f:
        db = json.load(f)
    for key in ['users', 'profiles', 'files', 'folders']:
        if key not in db:
            db[key] = []
    return db

def save_db(db):
    with open(DATA_FILE, 'w') as f:
        json.dump(db, f, indent=2)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def today_str():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d')

# ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
        if not token:
            return jsonify({'error': 'Token tidak ditemukan.'}), 401
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            request.user_id = payload['userId']
        except Exception:
            return jsonify({'error': 'Token tidak valid atau kadaluarsa.'}), 401
        return f(*args, **kwargs)
    return decorated

def make_token(user_id):
    payload = {
        'userId': user_id,
        'exp': datetime.now(timezone.utc) + timedelta(days=30)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def build_user_response(user, profile, db):
    # Hanya hitung file yang tidak di trash
    active_files  = [f for f in db['files']
                     if f['userId'] == user['id'] and not f.get('deletedAt')]
    total_files   = len(active_files)
    today_uploads = len([f for f in active_files
                         if f.get('uploadedAt', '').startswith(today_str())])
    total_size    = sum(f.get('size', 0) for f in active_files)
    return {
        'id':        user['id'],
        'username':  user['username'],
        'email':     user['email'],
        'createdAt': user.get('createdAt', now_iso()),
        'profile':   profile,
        'stats': {
            'totalFiles':   total_files,
            'todayUploads': today_uploads,
            'totalSize':    total_size,
        }
    }

# ── AUTH ──────────────────────────────────────────────────────────────────────
@app.route('/api/auth/register', methods=['POST'])
def register():
    data     = request.get_json() or {}
    username = (data.get('username') or '').strip()
    email    = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    if not username or not email or not password:
        return jsonify({'error': 'Semua kolom wajib diisi.'}), 400
    if len(username) < 3:
        return jsonify({'error': 'Username minimal 3 karakter.'}), 400
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return jsonify({'error': 'Format email tidak valid.'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password minimal 6 karakter.'}), 400

    db = load_db()
    if any(u['username'].lower() == username.lower() for u in db['users']):
        return jsonify({'error': 'Username sudah digunakan.'}), 409
    if any(u['email'] == email for u in db['users']):
        return jsonify({'error': 'Email sudah terdaftar.'}), 409

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user = {
        'id':        str(uuid.uuid4()),
        'username':  username,
        'email':     email,
        'password':  hashed,
        'createdAt': now_iso(),
    }
    profile = {
        'userId':      user['id'],
        'displayName': '',
        'bio':         '',
        'avatarColor': '#a78bfa',
        'avatarFile':  None,
    }
    db['users'].append(user)
    db['profiles'].append(profile)
    save_db(db)
    return jsonify({'message': 'Akun berhasil dibuat!'}), 201


@app.route('/api/auth/login', methods=['POST'])
def login():
    data       = request.get_json() or {}
    identifier = (data.get('identifier') or '').strip()
    password   = data.get('password') or ''

    if not identifier or not password:
        return jsonify({'error': 'Username/email dan password wajib diisi.'}), 400

    db   = load_db()
    user = next((u for u in db['users']
                 if u['username'].lower() == identifier.lower()
                 or u['email'].lower() == identifier.lower()), None)
    if not user or not bcrypt.checkpw(password.encode(), user['password'].encode()):
        return jsonify({'error': 'Username/email atau password salah.'}), 401

    profile = next((p for p in db['profiles'] if p['userId'] == user['id']), {})
    token   = make_token(user['id'])
    return jsonify({'token': token, 'user': build_user_response(user, profile, db)})


@app.route('/api/auth/verify', methods=['POST'])
@auth_required
def verify_token():
    db      = load_db()
    user    = next((u for u in db['users'] if u['id'] == request.user_id), None)
    if not user:
        return jsonify({'error': 'User tidak ditemukan.'}), 404
    profile = next((p for p in db['profiles'] if p['userId'] == user['id']), {})
    return jsonify({'user': build_user_response(user, profile, db)})


# ── PROFILE ───────────────────────────────────────────────────────────────────
@app.route('/api/profile', methods=['GET'])
@auth_required
def get_profile():
    db      = load_db()
    user    = next((u for u in db['users'] if u['id'] == request.user_id), None)
    if not user:
        return jsonify({'error': 'User tidak ditemukan.'}), 404
    profile = next((p for p in db['profiles'] if p['userId'] == user['id']), {})
    return jsonify(build_user_response(user, profile, db))


@app.route('/api/profile', methods=['PUT'])
@auth_required
def update_profile():
    data         = request.get_json() or {}
    display_name = (data.get('displayName') or '').strip()
    bio          = (data.get('bio') or '').strip()
    avatar_color = data.get('avatarColor') or '#a78bfa'

    db      = load_db()
    profile = next((p for p in db['profiles'] if p['userId'] == request.user_id), None)
    if not profile:
        profile = {'userId': request.user_id, 'displayName': '', 'bio': '',
                   'avatarColor': '#a78bfa', 'avatarFile': None}
        db['profiles'].append(profile)

    profile['displayName'] = display_name
    profile['bio']         = bio
    profile['avatarColor'] = avatar_color
    save_db(db)
    return jsonify({'message': 'Profil diperbarui.', 'profile': profile})


@app.route('/api/profile/password', methods=['PUT'])
@auth_required
def change_password():
    data             = request.get_json() or {}
    current_password = data.get('currentPassword') or ''
    new_password     = data.get('newPassword') or ''

    if not current_password or not new_password:
        return jsonify({'error': 'Semua kolom wajib diisi.'}), 400
    if len(new_password) < 6:
        return jsonify({'error': 'Password baru minimal 6 karakter.'}), 400

    db   = load_db()
    user = next((u for u in db['users'] if u['id'] == request.user_id), None)
    if not user:
        return jsonify({'error': 'User tidak ditemukan.'}), 404
    if not bcrypt.checkpw(current_password.encode(), user['password'].encode()):
        return jsonify({'error': 'Password saat ini salah.'}), 401

    user['password'] = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    save_db(db)
    return jsonify({'message': 'Password berhasil diperbarui.'})


@app.route('/api/profile/account', methods=['PUT'])
@auth_required
def change_account():
    data     = request.get_json() or {}
    username = (data.get('username') or '').strip()
    email    = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    if not password:
        return jsonify({'error': 'Password konfirmasi wajib diisi.'}), 400
    if not username and not email:
        return jsonify({'error': 'Isi minimal username atau email baru.'}), 400

    db   = load_db()
    user = next((u for u in db['users'] if u['id'] == request.user_id), None)
    if not user:
        return jsonify({'error': 'User tidak ditemukan.'}), 404
    if not bcrypt.checkpw(password.encode(), user['password'].encode()):
        return jsonify({'error': 'Password salah.'}), 401

    if username:
        if len(username) < 3:
            return jsonify({'error': 'Username minimal 3 karakter.'}), 400
        if any(u['username'].lower() == username.lower() and u['id'] != user['id']
               for u in db['users']):
            return jsonify({'error': 'Username sudah digunakan.'}), 409
        user['username'] = username
    if email:
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            return jsonify({'error': 'Format email tidak valid.'}), 400
        if any(u['email'] == email and u['id'] != user['id'] for u in db['users']):
            return jsonify({'error': 'Email sudah digunakan.'}), 409
        user['email'] = email

    save_db(db)
    profile = next((p for p in db['profiles'] if p['userId'] == user['id']), {})
    token   = make_token(user['id'])
    return jsonify({'message': 'Akun diperbarui.', 'token': token,
                    'user': build_user_response(user, profile, db)})


@app.route('/api/profile/account', methods=['DELETE'])
@auth_required
def delete_account():
    data     = request.get_json() or {}
    password = data.get('password') or ''

    if not password:
        return jsonify({'error': 'Password wajib diisi untuk konfirmasi.'}), 400

    db   = load_db()
    user = next((u for u in db['users'] if u['id'] == request.user_id), None)
    if not user:
        return jsonify({'error': 'User tidak ditemukan.'}), 404
    if not bcrypt.checkpw(password.encode(), user['password'].encode()):
        return jsonify({'error': 'Password salah.'}), 401

    uid = request.user_id

    # Hapus semua file fisik milik user
    for f in db['files']:
        if f['userId'] == uid:
            path = os.path.join(UPLOADS_DIR, f.get('storedName', ''))
            if os.path.exists(path):
                os.remove(path)

    # Hapus avatar fisik
    profile = next((p for p in db['profiles'] if p['userId'] == uid), None)
    if profile and profile.get('avatarFile'):
        av_path = os.path.join(PUBLIC_DIR, 'avatars', profile['avatarFile'])
        if os.path.exists(av_path):
            os.remove(av_path)

    db['users']    = [u for u in db['users']    if u['id']      != uid]
    db['profiles'] = [p for p in db['profiles'] if p['userId']  != uid]
    db['files']    = [f for f in db['files']    if f['userId']  != uid]
    db['folders']  = [fo for fo in db['folders'] if fo['userId'] != uid]
    save_db(db)
    return jsonify({'message': 'Akun berhasil dihapus.'})


# ── AVATAR ────────────────────────────────────────────────────────────────────
ALLOWED_AVATAR_EXTS = {'.jpg', '.jpeg', '.png', '.webp', '.gif'}

@app.route('/api/profile/avatar', methods=['POST'])
@auth_required
def upload_avatar():
    if 'avatar' not in request.files:
        return jsonify({'error': 'File avatar tidak ditemukan.'}), 400
    file = request.files['avatar']
    ext  = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_AVATAR_EXTS:
        return jsonify({'error': 'Format tidak didukung. Gunakan JPG, PNG, WEBP, atau GIF.'}), 400

    db      = load_db()
    profile = next((p for p in db['profiles'] if p['userId'] == request.user_id), None)
    if not profile:
        return jsonify({'error': 'Profil tidak ditemukan.'}), 404

    # Hapus avatar lama
    if profile.get('avatarFile'):
        old = os.path.join(PUBLIC_DIR, 'avatars', profile['avatarFile'])
        if os.path.exists(old):
            os.remove(old)

    filename = f"{request.user_id}{ext}"
    av_dir   = os.path.join(PUBLIC_DIR, 'avatars')
    os.makedirs(av_dir, exist_ok=True)
    file.save(os.path.join(av_dir, filename))

    profile['avatarFile'] = filename
    save_db(db)
    return jsonify({'message': 'Avatar berhasil diupload.', 'avatarFile': filename})


@app.route('/api/profile/avatar/<user_id>', methods=['GET'])
def get_avatar(user_id):
    av_dir = os.path.join(PUBLIC_DIR, 'avatars')
    for ext in ALLOWED_AVATAR_EXTS:
        path = os.path.join(av_dir, f"{user_id}{ext}")
        if os.path.exists(path):
            return send_file(path)
    return jsonify({'error': 'Avatar tidak ditemukan.'}), 404


@app.route('/api/profile/avatar', methods=['DELETE'])
@auth_required
def remove_avatar():
    db      = load_db()
    profile = next((p for p in db['profiles'] if p['userId'] == request.user_id), None)
    if not profile:
        return jsonify({'error': 'Profil tidak ditemukan.'}), 404

    if profile.get('avatarFile'):
        path = os.path.join(PUBLIC_DIR, 'avatars', profile['avatarFile'])
        if os.path.exists(path):
            os.remove(path)
        profile['avatarFile'] = None
        save_db(db)
    return jsonify({'message': 'Avatar berhasil dihapus.'})


# ── FOLDERS ───────────────────────────────────────────────────────────────────
@app.route('/api/folders', methods=['GET'])
@auth_required
def get_folders():
    db      = load_db()
    folders = [fo for fo in db['folders'] if fo['userId'] == request.user_id]
    return jsonify({'folders': folders})


@app.route('/api/folders', methods=['POST'])
@auth_required
def create_folder():
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Nama folder tidak boleh kosong.'}), 400

    db = load_db()
    if any(fo['name'].lower() == name.lower() and fo['userId'] == request.user_id
           for fo in db['folders']):
        return jsonify({'error': 'Folder dengan nama ini sudah ada.'}), 409

    folder = {
        'id':        str(uuid.uuid4()),
        'userId':    request.user_id,
        'name':      name,
        'createdAt': now_iso(),
    }
    db['folders'].append(folder)
    save_db(db)
    return jsonify({'folder': folder}), 201


@app.route('/api/folders/<folder_id>', methods=['PUT'])
@auth_required
def rename_folder(folder_id):
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Nama tidak boleh kosong.'}), 400

    db     = load_db()
    folder = next((fo for fo in db['folders']
                   if fo['id'] == folder_id and fo['userId'] == request.user_id), None)
    if not folder:
        return jsonify({'error': 'Folder tidak ditemukan.'}), 404

    folder['name'] = name
    save_db(db)
    return jsonify({'folder': folder})


@app.route('/api/folders/<folder_id>', methods=['DELETE'])
@auth_required
def delete_folder(folder_id):
    db     = load_db()
    folder = next((fo for fo in db['folders']
                   if fo['id'] == folder_id and fo['userId'] == request.user_id), None)
    if not folder:
        return jsonify({'error': 'Folder tidak ditemukan.'}), 404

    # Pindah semua file ke root (termasuk yang di trash)
    for f in db['files']:
        if f.get('folderId') == folder_id and f['userId'] == request.user_id:
            f['folderId'] = None

    db['folders'] = [fo for fo in db['folders'] if fo['id'] != folder_id]
    save_db(db)
    return jsonify({'message': 'Folder berhasil dihapus.'})


# ── FILES ─────────────────────────────────────────────────────────────────────
@app.route('/api/files', methods=['GET'])
@auth_required
def get_files():
    db    = load_db()
    # Exclude file yang ada di trash
    files = [f for f in db['files']
             if f['userId'] == request.user_id and not f.get('deletedAt')]
    return jsonify({'files': files})


@app.route('/api/files/upload', methods=['POST'])
@auth_required
def upload_files():
    if 'files' not in request.files:
        return jsonify({'error': 'Tidak ada file yang diupload.'}), 400

    folder_id = request.form.get('folderId') or None
    db        = load_db()
    uploaded  = []

    for file in request.files.getlist('files'):
        if not file.filename:
            continue
        original_name = secure_filename(file.filename)
        ext           = os.path.splitext(original_name)[1].lower()
        stored_name   = uuid.uuid4().hex + ext
        file_path     = os.path.join(UPLOADS_DIR, stored_name)
        file.save(file_path)
        size = os.path.getsize(file_path)

        record = {
            'id':           str(uuid.uuid4()),
            'userId':       request.user_id,
            'originalName': original_name,
            'storedName':   stored_name,
            'size':         size,
            'folderId':     folder_id,
            'uploadedAt':   now_iso(),
        }
        db['files'].append(record)
        uploaded.append(record)

    save_db(db)
    return jsonify({'message': f'{len(uploaded)} file berhasil diupload.', 'files': uploaded}), 201


@app.route('/api/files/<file_id>', methods=['PUT'])
@auth_required
def update_file(file_id):
    data = request.get_json() or {}
    db   = load_db()
    f    = next((x for x in db['files']
                 if x['id'] == file_id and x['userId'] == request.user_id
                 and not x.get('deletedAt')), None)
    if not f:
        return jsonify({'error': 'File tidak ditemukan.'}), 404

    if 'originalName' in data:
        new_name = (data['originalName'] or '').strip()
        if not new_name:
            return jsonify({'error': 'Nama tidak boleh kosong.'}), 400
        f['originalName'] = new_name

    if 'folderId' in data:
        folder_id = data['folderId']
        if folder_id is not None:
            folder_exists = any(fo['id'] == folder_id and fo['userId'] == request.user_id
                                for fo in db['folders'])
            if not folder_exists:
                return jsonify({'error': 'Folder tidak ditemukan.'}), 404
        f['folderId'] = folder_id

    save_db(db)
    return jsonify({'file': f})


@app.route('/api/files/<file_id>', methods=['DELETE'])
@auth_required
def delete_file(file_id):
    db = load_db()
    f  = next((x for x in db['files']
               if x['id'] == file_id and x['userId'] == request.user_id
               and not x.get('deletedAt')), None)
    if not f:
        return jsonify({'error': 'File tidak ditemukan.'}), 404

    # Soft-delete: tandai deletedAt, file fisik tetap ada
    f['deletedAt'] = now_iso()
    save_db(db)
    return jsonify({'message': 'File dipindah ke trash.'})


@app.route('/api/files/<file_id>/download', methods=['GET'])
@auth_required
def download_file(file_id):
    db = load_db()
    f  = next((x for x in db['files']
               if x['id'] == file_id and x['userId'] == request.user_id), None)
    if not f:
        return jsonify({'error': 'File tidak ditemukan.'}), 404

    path = os.path.join(UPLOADS_DIR, f.get('storedName', ''))
    if not os.path.exists(path):
        return jsonify({'error': 'File fisik tidak ditemukan di server.'}), 404

    mime = mimetypes.guess_type(f['originalName'])[0] or 'application/octet-stream'
    return send_file(path, mimetype=mime,
                     as_attachment=False,
                     download_name=f['originalName'])


# ── TRASH ─────────────────────────────────────────────────────────────────────
@app.route('/api/trash', methods=['GET'])
@auth_required
def get_trash():
    db    = load_db()
    files = [f for f in db['files']
             if f['userId'] == request.user_id and f.get('deletedAt')]
    files.sort(key=lambda x: x.get('deletedAt', ''), reverse=True)
    return jsonify({'files': files})


@app.route('/api/trash/<file_id>/restore', methods=['POST'])
@auth_required
def restore_file(file_id):
    db = load_db()
    f  = next((x for x in db['files']
               if x['id'] == file_id and x['userId'] == request.user_id
               and x.get('deletedAt')), None)
    if not f:
        return jsonify({'error': 'File tidak ditemukan di trash.'}), 404

    # Kalau folder sudah dihapus, pindah ke root
    if f.get('folderId'):
        folder_exists = any(fo['id'] == f['folderId'] and fo['userId'] == request.user_id
                            for fo in db['folders'])
        if not folder_exists:
            f['folderId'] = None

    del f['deletedAt']
    save_db(db)
    return jsonify({'message': 'File berhasil direstore.', 'file': f})


@app.route('/api/trash/<file_id>', methods=['DELETE'])
@auth_required
def delete_permanent(file_id):
    db = load_db()
    f  = next((x for x in db['files']
               if x['id'] == file_id and x['userId'] == request.user_id
               and x.get('deletedAt')), None)
    if not f:
        return jsonify({'error': 'File tidak ditemukan di trash.'}), 404

    # Hapus file fisik
    path = os.path.join(UPLOADS_DIR, f.get('storedName', ''))
    if os.path.exists(path):
        os.remove(path)

    db['files'] = [x for x in db['files'] if x['id'] != file_id]
    save_db(db)
    return jsonify({'message': 'File dihapus permanen.'})


@app.route('/api/trash', methods=['DELETE'])
@auth_required
def empty_trash():
    db    = load_db()
    trash = [f for f in db['files']
             if f['userId'] == request.user_id and f.get('deletedAt')]
    for f in trash:
        path = os.path.join(UPLOADS_DIR, f.get('storedName', ''))
        if os.path.exists(path):
            os.remove(path)

    db['files'] = [f for f in db['files']
                   if not (f['userId'] == request.user_id and f.get('deletedAt'))]
    save_db(db)
    return jsonify({'message': f'{len(trash)} file dihapus permanen.'})


# ── REMOVE BACKGROUND ─────────────────────────────────────────────────────────
RMBG_API_KEY = os.environ.get('REMOVE_BG_API_KEY', '')

@app.route('/api/files/<file_id>/remove-bg', methods=['POST'])
@auth_required
def remove_bg(file_id):
    if not RMBG_API_KEY:
        return jsonify({'error': 'Fitur hapus background belum dikonfigurasi (API key tidak ada).'}), 503

    db = load_db()
    f  = next((x for x in db['files']
               if x['id'] == file_id and x['userId'] == request.user_id
               and not x.get('deletedAt')), None)
    if not f:
        return jsonify({'error': 'File tidak ditemukan.'}), 404

    path = os.path.join(UPLOADS_DIR, f.get('storedName', ''))
    if not os.path.exists(path):
        return jsonify({'error': 'File fisik tidak ditemukan.'}), 404

    try:
        with open(path, 'rb') as img:
            resp = requests.post(
                'https://api.remove.bg/v1.0/removebg',
                files={'image_file': img},
                data={'size': 'auto'},
                headers={'X-Api-Key': RMBG_API_KEY},
                timeout=60
            )
        if resp.status_code != 200:
            msg = resp.json().get('errors', [{}])[0].get('title', 'Gagal hapus background.')
            return jsonify({'error': msg}), 502

        req_data  = request.get_json(silent=True) or {}
        folder_id = req_data.get('folderId') or None
        base_name = os.path.splitext(f['originalName'])[0]
        new_name  = f"{base_name}_nobg.png"
        stored    = uuid.uuid4().hex + '.png'
        out_path  = os.path.join(UPLOADS_DIR, stored)

        with open(out_path, 'wb') as out:
            out.write(resp.content)

        record = {
            'id':           str(uuid.uuid4()),
            'userId':       request.user_id,
            'originalName': new_name,
            'storedName':   stored,
            'size':         os.path.getsize(out_path),
            'folderId':     folder_id,
            'uploadedAt':   now_iso(),
        }
        db['files'].append(record)
        save_db(db)
        return jsonify({'file': record})

    except requests.exceptions.Timeout:
        return jsonify({'error': 'Request ke remove.bg timeout. Coba lagi.'}), 504
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── SCANNER ───────────────────────────────────────────────────────────────────
@app.route('/api/scan/upload', methods=['POST'])
@auth_required
def scan_upload():
    if 'image' not in request.files:
        return jsonify({'error': 'Tidak ada gambar.'}), 400

    file = request.files['image']
    if not file.filename:
        return jsonify({'error': 'File gambar tidak valid.'}), 400

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ['.jpg', '.jpeg', '.png', '.webp', '.gif']:
        return jsonify({'error': 'Format tidak didukung.'}), 400

    scan_dir    = os.path.join(PUBLIC_DIR, 'scans')
    os.makedirs(scan_dir, exist_ok=True)
    unique_name = uuid.uuid4().hex + ext
    path        = os.path.join(scan_dir, unique_name)
    file.save(path)

    def delete_later():
        time.sleep(300)
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass

    threading.Thread(target=delete_later, daemon=True).start()
    host = request.host_url.rstrip('/')
    return jsonify({'url': f"{host}/scans/{unique_name}"})


# ── STATIC FILES ──────────────────────────────────────────────────────────────
@app.route('/scans/<filename>')
def serve_scan(filename):
    return send_from_directory(os.path.join(PUBLIC_DIR, 'scans'), filename)

@app.route('/')
def index():
    return send_from_directory(PUBLIC_DIR, 'index.html')

@app.errorhandler(404)
def not_found(e):
    index_path = os.path.join(PUBLIC_DIR, 'index.html')
    if os.path.exists(index_path):
        return send_from_directory(PUBLIC_DIR, 'index.html')
    return jsonify({'error': 'Not found'}), 404


# ── ENTRY POINT ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print(f"🚀 Veilfile Backend started on port {PORT}")
    print(f"   Uploads : {UPLOADS_DIR}")
    print(f"   Public  : {PUBLIC_DIR}")
    print(f"   DB      : {DATA_FILE}")
    print(f"   Remove.bg: {'✅ configured' if RMBG_API_KEY else '⚠️  not configured (set REMOVE_BG_API_KEY)'}")
    app.run(host='0.0.0.0', port=PORT, debug=False)