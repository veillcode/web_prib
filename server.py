from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
import json, os, uuid, bcrypt, jwt, re, base64, mimetypes
from datetime import datetime, timedelta, timezone
from functools import wraps
from werkzeug.utils import secure_filename
import requests

# ── Config ────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DATA_FILE   = os.path.join(BASE_DIR, 'data', 'db.json')
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')
AVATARS_DIR = os.path.join(BASE_DIR, 'avatars')
PUBLIC_DIR  = os.path.join(BASE_DIR, 'public')
JWT_SECRET  = os.environ.get('JWT_SECRET', 'veilfile_secret_python_2025')
JWT_DAYS    = 7
PORT        = int(os.environ.get('PORT', 3001))
MAX_MB      = 50

os.makedirs(os.path.join(BASE_DIR, 'data'), exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(AVATARS_DIR, exist_ok=True)

ALLOWED_AVATAR_EXT = {'.jpg', '.jpeg', '.png', '.webp', '.gif'}
MAX_AVATAR_MB      = 5

app = Flask(__name__, static_folder=PUBLIC_DIR, static_url_path='')
CORS(app)
app.config['MAX_CONTENT_LENGTH'] = MAX_MB * 1024 * 1024

# ── Database ──────────────────────────────────────
def load_db():
    if not os.path.exists(DATA_FILE):
        return {'users': [], 'profiles': [], 'files': [], 'folders': []}
    db = json.load(open(DATA_FILE, 'r'))
    if 'folders' not in db:
        db['folders'] = []
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
    return jwt.encode(
        {'userId': user_id, 'username': username, 'exp': exp},
        JWT_SECRET, algorithm='HS256'
    )

COLORS = ['#a78bfa','#60a5fa','#f472b6','#34d399','#fb923c','#facc15','#e879f9']

# ══════════════════════════════════════════════════
#  STATIC
# ══════════════════════════════════════════════════
@app.route('/')
def index():
    return send_from_directory(PUBLIC_DIR, 'index.html')

# ══════════════════════════════════════════════════
#  AUTH
# ══════════════════════════════════════════════════
@app.route('/api/auth/register', methods=['POST'])
def register():
    body     = request.get_json() or {}
    username = (body.get('username') or '').strip()
    email    = (body.get('email') or '').strip()
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
    now     = datetime.now(timezone.utc).isoformat()
    hashed  = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    db['users'].append({
        'id': user_id, 'username': username, 'email': email,
        'password': hashed, 'createdAt': now
    })
    db['profiles'].append({
        'userId': user_id, 'displayName': username, 'bio': '',
        'avatarColor': random.choice(COLORS),
        'avatarFile': None,
        'createdAt': now, 'updatedAt': now
    })
    save_db(db)
    return jsonify({'message': 'Akun berhasil dibuat!'}), 201


@app.route('/api/auth/login', methods=['POST'])
def login():
    body       = request.get_json() or {}
    identifier = (body.get('identifier') or '').strip()
    password   = body.get('password') or ''

    if not identifier or not password:
        return jsonify({'error': 'Harap isi semua kolom.'}), 400

    db   = load_db()
    user = next((u for u in db['users']
                 if u['username'].lower() == identifier.lower()
                 or u['email'].lower()    == identifier.lower()), None)

    if not user:
        return jsonify({'error': 'Akun belum terdaftar.'}), 401
    if not bcrypt.checkpw(password.encode(), user['password'].encode()):
        return jsonify({'error': 'Password yang anda masukkan salah.'}), 401

    profile = next((p for p in db['profiles'] if p['userId'] == user['id']), {})
    token   = make_token(user['id'], user['username'])
    return jsonify({
        'token': token,
        'user': {
            'id': user['id'], 'username': user['username'],
            'email': user['email'], 'createdAt': user['createdAt'],
            'profile': profile
        }
    })


@app.route('/api/auth/verify', methods=['POST'])
@auth_required
def verify():
    db   = load_db()
    user = next((u for u in db['users'] if u['id'] == request.user_id), None)
    if not user:
        return jsonify({'error': 'User tidak ditemukan.'}), 404
    profile = next((p for p in db['profiles'] if p['userId'] == request.user_id), {})
    return jsonify({
        'user': {
            'id': user['id'], 'username': user['username'],
            'email': user['email'], 'createdAt': user['createdAt'],
            'profile': profile
        }
    })

# ══════════════════════════════════════════════════
#  PROFILE
# ══════════════════════════════════════════════════
@app.route('/api/profile', methods=['GET'])
@auth_required
def get_profile():
    db      = load_db()
    user    = next((u for u in db['users']    if u['id'] == request.user_id), None)
    profile = next((p for p in db['profiles'] if p['userId'] == request.user_id), {})
    if not user:
        return jsonify({'error': 'User tidak ditemukan.'}), 404

    files     = [f for f in db['files'] if f['userId'] == request.user_id]
    today_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    today_ct  = sum(1 for f in files if f.get('uploadedAt', '').startswith(today_str))
    total_sz  = sum(f.get('size', 0) for f in files)

    return jsonify({
        'id': user['id'], 'username': user['username'], 'email': user['email'],
        'createdAt': user['createdAt'], 'profile': profile,
        'stats': {'totalFiles': len(files), 'totalSize': total_sz, 'todayUploads': today_ct}
    })


@app.route('/api/profile', methods=['PUT'])
@auth_required
def update_profile():
    body = request.get_json() or {}
    db   = load_db()
    now  = datetime.now(timezone.utc).isoformat()
    for p in db['profiles']:
        if p['userId'] == request.user_id:
            if 'displayName' in body: p['displayName'] = str(body['displayName'])[:50]
            if 'bio'         in body: p['bio']         = str(body['bio'])[:200]
            if 'avatarColor' in body: p['avatarColor'] = body['avatarColor']
            p['updatedAt'] = now
            save_db(db)
            return jsonify({'message': 'Profil berhasil diperbarui.', 'profile': p})
    return jsonify({'error': 'Profil tidak ditemukan.'}), 404


@app.route('/api/profile/avatar', methods=['POST'])
@auth_required
def upload_avatar():
    if 'avatar' not in request.files:
        return jsonify({'error': 'Tidak ada file avatar yang dikirim.'}), 400

    file = request.files['avatar']
    if not file.filename:
        return jsonify({'error': 'Nama file tidak valid.'}), 400

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_AVATAR_EXT:
        return jsonify({'error': 'Format tidak didukung. Gunakan JPG, PNG, WEBP, atau GIF.'}), 400

    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    if size > MAX_AVATAR_MB * 1024 * 1024:
        return jsonify({'error': f'Ukuran file maksimal {MAX_AVATAR_MB}MB.'}), 400

    db      = load_db()
    profile = next((p for p in db['profiles'] if p['userId'] == request.user_id), None)
    if not profile:
        return jsonify({'error': 'Profil tidak ditemukan.'}), 404

    # Hapus avatar lama jika ada
    old_avatar = profile.get('avatarFile')
    if old_avatar:
        old_path = os.path.join(AVATARS_DIR, old_avatar)
        if os.path.exists(old_path):
            os.remove(old_path)

    unique_name = uuid.uuid4().hex + ext
    save_path   = os.path.join(AVATARS_DIR, unique_name)
    file.save(save_path)

    profile['avatarFile'] = unique_name
    profile['updatedAt']  = datetime.now(timezone.utc).isoformat()
    save_db(db)

    return jsonify({
        'message':    'Foto profil berhasil diupload!',
        'avatarFile': unique_name,
        'avatarUrl':  f'/api/profile/avatar/{request.user_id}'
    })


@app.route('/api/profile/avatar/<user_id>', methods=['GET'])
def get_avatar(user_id):
    db      = load_db()
    profile = next((p for p in db['profiles'] if p['userId'] == user_id), None)
    if not profile or not profile.get('avatarFile'):
        return jsonify({'error': 'Avatar tidak ditemukan.'}), 404

    path = os.path.join(AVATARS_DIR, profile['avatarFile'])
    if not os.path.exists(path):
        return jsonify({'error': 'File avatar tidak ada di server.'}), 404

    return send_file(path)


# ── FIX: delete_avatar yang sebelumnya hanya berisi `...` ────────────────────
@app.route('/api/profile/avatar', methods=['DELETE'])
@auth_required
def delete_avatar():
    db      = load_db()
    profile = next((p for p in db['profiles'] if p['userId'] == request.user_id), None)
    if not profile:
        return jsonify({'error': 'Profil tidak ditemukan.'}), 404

    avatar_file = profile.get('avatarFile')
    if avatar_file:
        avatar_path = os.path.join(AVATARS_DIR, avatar_file)
        if os.path.exists(avatar_path):
            os.remove(avatar_path)
        profile['avatarFile'] = None
        profile['updatedAt']  = datetime.now(timezone.utc).isoformat()
        save_db(db)

    return jsonify({'message': 'Avatar berhasil dihapus.'})


@app.route('/api/profile/password', methods=['PUT'])
@auth_required
def change_password():
    body    = request.get_json() or {}
    curr_pw = body.get('currentPassword') or ''
    new_pw  = body.get('newPassword') or ''
    if not curr_pw or not new_pw:
        return jsonify({'error': 'Semua kolom harus diisi.'}), 400
    if len(new_pw) < 6:
        return jsonify({'error': 'Password baru minimal 6 karakter.'}), 400
    db   = load_db()
    user = next((u for u in db['users'] if u['id'] == request.user_id), None)
    if not user:
        return jsonify({'error': 'User tidak ditemukan.'}), 404
    if not bcrypt.checkpw(curr_pw.encode(), user['password'].encode()):
        return jsonify({'error': 'Password saat ini tidak sesuai.'}), 401
    user['password'] = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
    save_db(db)
    return jsonify({'message': 'Password berhasil diperbarui.'})


@app.route('/api/profile/account', methods=['PUT'])
@auth_required
def update_account():
    body         = request.get_json() or {}
    new_username = (body.get('username') or '').strip()
    new_email    = (body.get('email') or '').strip()
    password     = body.get('password') or ''

    if not password:
        return jsonify({'error': 'Konfirmasi password diperlukan.'}), 400
    if not new_username and not new_email:
        return jsonify({'error': 'Isi minimal satu kolom (username atau email).'}), 400

    db   = load_db()
    user = next((u for u in db['users'] if u['id'] == request.user_id), None)
    if not user:
        return jsonify({'error': 'User tidak ditemukan.'}), 404
    if not bcrypt.checkpw(password.encode(), user['password'].encode()):
        return jsonify({'error': 'Password tidak sesuai.'}), 401

    if new_username and new_username.lower() != user['username'].lower():
        if any(u['username'].lower() == new_username.lower()
               for u in db['users'] if u['id'] != request.user_id):
            return jsonify({'error': 'Username sudah digunakan oleh akun lain.'}), 409
        for p in db['profiles']:
            if p['userId'] == request.user_id and p.get('displayName') == user['username']:
                p['displayName'] = new_username
        user['username'] = new_username

    if new_email:
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', new_email):
            return jsonify({'error': 'Format email tidak valid.'}), 400
        if new_email.lower() != user['email'].lower():
            if any(u['email'].lower() == new_email.lower()
                   for u in db['users'] if u['id'] != request.user_id):
                return jsonify({'error': 'Email sudah digunakan oleh akun lain.'}), 409
            user['email'] = new_email

    save_db(db)
    new_token = make_token(user['id'], user['username'])
    profile   = next((p for p in db['profiles'] if p['userId'] == request.user_id), {})
    return jsonify({
        'message': 'Akun berhasil diperbarui.',
        'token': new_token,
        'user': {
            'id': user['id'], 'username': user['username'],
            'email': user['email'], 'createdAt': user['createdAt'],
            'profile': profile
        }
    })


@app.route('/api/profile/account', methods=['DELETE'])
@auth_required
def delete_account():
    body     = request.get_json() or {}
    password = body.get('password') or ''

    if not password:
        return jsonify({'error': 'Konfirmasi password diperlukan.'}), 400

    db   = load_db()
    user = next((u for u in db['users'] if u['id'] == request.user_id), None)
    if not user:
        return jsonify({'error': 'User tidak ditemukan.'}), 404
    if not bcrypt.checkpw(password.encode(), user['password'].encode()):
        return jsonify({'error': 'Password tidak sesuai.'}), 401

    # Hapus semua file upload milik user
    user_dir = os.path.join(UPLOADS_DIR, request.user_id)
    if os.path.exists(user_dir):
        import shutil
        shutil.rmtree(user_dir, ignore_errors=True)

    # Hapus avatar jika ada
    profile = next((p for p in db['profiles'] if p['userId'] == request.user_id), None)
    if profile and profile.get('avatarFile'):
        avatar_path = os.path.join(AVATARS_DIR, profile['avatarFile'])
        if os.path.exists(avatar_path):
            os.remove(avatar_path)

    db['users']    = [u for u in db['users']    if u['id']     != request.user_id]
    db['profiles'] = [p for p in db['profiles'] if p['userId'] != request.user_id]
    db['files']    = [f for f in db['files']    if f['userId'] != request.user_id]
    db['folders']  = [f for f in db['folders']  if f['userId'] != request.user_id]
    save_db(db)

    return jsonify({'message': 'Akun berhasil dihapus.'})

# ══════════════════════════════════════════════════
#  FOLDERS
# ══════════════════════════════════════════════════
@app.route('/api/folders', methods=['GET'])
@auth_required
def list_folders():
    db      = load_db()
    folders = [f for f in db['folders'] if f['userId'] == request.user_id]
    folders.sort(key=lambda x: x.get('createdAt', ''))
    return jsonify({'folders': folders})


@app.route('/api/folders', methods=['POST'])
@auth_required
def create_folder():
    body = request.get_json() or {}
    name = (body.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Nama folder tidak boleh kosong.'}), 400
    if len(name) > 60:
        return jsonify({'error': 'Nama folder maksimal 60 karakter.'}), 400

    db = load_db()
    if any(f['name'].lower() == name.lower() and f['userId'] == request.user_id
           for f in db['folders']):
        return jsonify({'error': 'Nama folder sudah ada.'}), 409

    folder = {
        'id':        'folder_' + uuid.uuid4().hex[:10],
        'userId':    request.user_id,
        'name':      name,
        'createdAt': datetime.now(timezone.utc).isoformat()
    }
    db['folders'].append(folder)
    save_db(db)
    return jsonify({'message': 'Folder berhasil dibuat.', 'folder': folder}), 201


@app.route('/api/folders/<folder_id>', methods=['PUT'])
@auth_required
def rename_folder(folder_id):
    body = request.get_json() or {}
    name = (body.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Nama folder tidak boleh kosong.'}), 400

    db     = load_db()
    folder = next((f for f in db['folders']
                   if f['id'] == folder_id and f['userId'] == request.user_id), None)
    if not folder:
        return jsonify({'error': 'Folder tidak ditemukan.'}), 404

    folder['name'] = name
    save_db(db)
    return jsonify({'message': 'Folder berhasil diubah.', 'folder': folder})


@app.route('/api/folders/<folder_id>', methods=['DELETE'])
@auth_required
def delete_folder(folder_id):
    db     = load_db()
    folder = next((f for f in db['folders']
                   if f['id'] == folder_id and f['userId'] == request.user_id), None)
    if not folder:
        return jsonify({'error': 'Folder tidak ditemukan.'}), 404

    for f in db['files']:
        if f.get('folderId') == folder_id:
            f['folderId'] = None

    db['folders'] = [f for f in db['folders'] if f['id'] != folder_id]
    save_db(db)
    return jsonify({'message': 'Folder berhasil dihapus. File dipindah ke root.'})

# ══════════════════════════════════════════════════
#  FILES
# ══════════════════════════════════════════════════
@app.route('/api/files', methods=['GET'])
@auth_required
def list_files():
    db    = load_db()
    files = [f for f in db['files'] if f['userId'] == request.user_id]
    files.sort(key=lambda x: x.get('uploadedAt', ''), reverse=True)
    return jsonify({'files': files})


@app.route('/api/files/upload', methods=['POST'])
@auth_required
def upload_files():
    if 'files' not in request.files:
        return jsonify({'error': 'Tidak ada file yang diupload.'}), 400

    folder_id = request.form.get('folderId') or None
    uploaded  = request.files.getlist('files')
    db        = load_db()
    saved     = []
    user_dir  = os.path.join(UPLOADS_DIR, request.user_id)
    os.makedirs(user_dir, exist_ok=True)

    for file in uploaded:
        if not file.filename:
            continue
        orig_name   = file.filename
        safe_name   = secure_filename(orig_name)
        unique_name = uuid.uuid4().hex + os.path.splitext(safe_name)[1]
        file_path   = os.path.join(user_dir, unique_name)
        file.save(file_path)
        size = os.path.getsize(file_path)
        now  = datetime.now(timezone.utc).isoformat()

        record = {
            'id':           'file_' + uuid.uuid4().hex[:12],
            'userId':       request.user_id,
            'originalName': orig_name,
            'storedName':   unique_name,
            'size':         size,
            'folderId':     folder_id,
            'uploadedAt':   now
        }
        db['files'].append(record)
        saved.append(record)

    save_db(db)
    return jsonify({'message': f'{len(saved)} file berhasil diupload!', 'files': saved}), 201


@app.route('/api/files/<file_id>', methods=['PUT'])
@auth_required
def update_file(file_id):
    body = request.get_json() or {}
    db   = load_db()
    file = next((f for f in db['files']
                 if f['id'] == file_id and f['userId'] == request.user_id), None)
    if not file:
        return jsonify({'error': 'File tidak ditemukan.'}), 404

    if 'originalName' in body:
        new_name = body['originalName'].strip()
        if not new_name:
            return jsonify({'error': 'Nama file tidak boleh kosong.'}), 400
        old_ext = os.path.splitext(file['originalName'])[1]
        new_ext = os.path.splitext(new_name)[1]
        if not new_ext:
            new_name = new_name + old_ext
        file['originalName'] = new_name

    if 'folderId' in body:
        file['folderId'] = body['folderId']

    save_db(db)
    return jsonify({'message': 'File berhasil diperbarui.', 'file': file})


@app.route('/api/files/<file_id>', methods=['DELETE'])
@auth_required
def delete_file(file_id):
    db   = load_db()
    file = next((f for f in db['files']
                 if f['id'] == file_id and f['userId'] == request.user_id
                 and not f.get('deletedAt')), None)
    if not file:
        return jsonify({'error': 'File tidak ditemukan.'}), 404

    # Soft-delete: tandai deletedAt, file fisik tetap ada
    file['deletedAt'] = datetime.now(timezone.utc).isoformat()
    save_db(db)
    return jsonify({'message': 'File dipindah ke trash.'})


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

    path = os.path.join(UPLOADS_DIR, request.user_id, f.get('storedName', ''))
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
        path = os.path.join(UPLOADS_DIR, request.user_id, f.get('storedName', ''))
        if os.path.exists(path):
            os.remove(path)
    db['files'] = [f for f in db['files']
                   if not (f['userId'] == request.user_id and f.get('deletedAt'))]
    save_db(db)
    return jsonify({'message': f'{len(trash)} file dihapus permanen.'})


# ── FIX: as_attachment=False agar file bisa dipreview di viewer ──────────────
@app.route('/api/files/<file_id>/download', methods=['GET'])
@auth_required
def download_file(file_id):
    db   = load_db()
    file = next((f for f in db['files']
                 if f['id'] == file_id and f['userId'] == request.user_id), None)
    if not file:
        return jsonify({'error': 'File tidak ditemukan.'}), 404

    path = os.path.join(UPLOADS_DIR, request.user_id, file['storedName'])
    if not os.path.exists(path):
        return jsonify({'error': 'File tidak ada di server.'}), 404

    mime = mimetypes.guess_type(file['originalName'])[0] or 'application/octet-stream'
    return send_file(
        path,
        mimetype=mime,
        as_attachment=False,          # ← preview di browser/viewer
        download_name=file['originalName']
    )


@app.route('/api/files/<file_id>/remove-bg', methods=['POST'])
@auth_required
def remove_bg(file_id):
    db   = load_db()
    file = next((f for f in db['files']
                 if f['id'] == file_id and f['userId'] == request.user_id), None)
    if not file:
        return jsonify({'error': 'File tidak ditemukan.'}), 404

    ext = os.path.splitext(file['originalName'])[1].lower()
    if ext not in ['.jpg', '.jpeg', '.png', '.webp', '.bmp']:
        return jsonify({'error': 'Format file tidak didukung. Gunakan JPG, PNG, atau WEBP.'}), 400

    src_path = os.path.join(UPLOADS_DIR, request.user_id, file['storedName'])
    if not os.path.exists(src_path):
        return jsonify({'error': 'File tidak ada di server.'}), 404

    api_key = os.environ.get('REMOVE_BG_API_KEY', 'gf4xMfqSYL4aD9JCiR7WeqZP')
    if not api_key:
        return jsonify({'error': 'Fitur hapus background belum dikonfigurasi.'}), 503

    try:
        with open(src_path, 'rb') as f:
            response = requests.post(
                'https://api.remove.bg/v1.0/removebg',
                files={'image_file': ('image', f)},
                data={'size': 'auto'},
                headers={'X-Api-Key': api_key},
                timeout=60
            )
        if response.status_code != 200:
            msg = response.json().get('errors', [{}])[0].get('title', 'Remove.bg error')
            return jsonify({'error': msg}), 502

        base_name   = os.path.splitext(file['originalName'])[0]
        new_orig    = base_name + '_no-bg.png'
        unique_name = uuid.uuid4().hex + '.png'
        user_dir    = os.path.join(UPLOADS_DIR, request.user_id)
        out_path    = os.path.join(user_dir, unique_name)

        with open(out_path, 'wb') as f:
            f.write(response.content)

        req_body  = request.get_json(silent=True) or {}
        folder_id = req_body.get('folderId') or file.get('folderId')
        now       = datetime.now(timezone.utc).isoformat()

        record = {
            'id':           'file_' + uuid.uuid4().hex[:12],
            'userId':       request.user_id,
            'originalName': new_orig,
            'storedName':   unique_name,
            'size':         os.path.getsize(out_path),
            'folderId':     folder_id,
            'uploadedAt':   now
        }
        db['files'].append(record)
        save_db(db)
        return jsonify({'message': 'Background berhasil dihapus!', 'file': record}), 201

    except requests.exceptions.Timeout:
        return jsonify({'error': 'Request timeout. Coba lagi.'}), 504
    except Exception as e:
        return jsonify({'error': f'Gagal memproses gambar: {str(e)}'}), 500


# ══════════════════════════════════════════════════
#  SCANNER
# ══════════════════════════════════════════════════
@app.route('/api/scan/upload', methods=['POST'])
@auth_required
def scan_upload():
    if 'image' not in request.files:
        return jsonify({'error': 'Tidak ada gambar.'}), 400

    file = request.files['image']
    ext  = os.path.splitext(file.filename)[1].lower()
    if ext not in ['.jpg', '.jpeg', '.png', '.webp', '.gif', '.bmp']:
        return jsonify({'error': 'Format tidak didukung.'}), 400

    unique_name = uuid.uuid4().hex + ext
    scan_dir    = os.path.join(PUBLIC_DIR, 'scans')
    os.makedirs(scan_dir, exist_ok=True)
    path = os.path.join(scan_dir, unique_name)
    file.save(path)

    import threading, time
    def delete_later():
        time.sleep(300)
        if os.path.exists(path):
            os.remove(path)
    threading.Thread(target=delete_later, daemon=True).start()

    host = request.host_url.rstrip('/')
    return jsonify({'url': f'{host}/scans/{unique_name}'})


@app.route('/scans/<filename>')
def serve_scan(filename):
    return send_from_directory(os.path.join(PUBLIC_DIR, 'scans'), filename)


# ══════════════════════════════════════════════════
if __name__ == '__main__':
    print(f'\n🚀 Veilfile Python Backend')
    print(f'🌐 http://localhost:{PORT}')
    print(f'📁 Database : {DATA_FILE}')
    print(f'📂 Uploads  : {UPLOADS_DIR}')
    print(f'🖼️  Avatars  : {AVATARS_DIR}')
    print(f'🎨 Remove.bg: {"✅ configured" if os.environ.get("REMOVE_BG_API_KEY") else "⚠️  set REMOVE_BG_API_KEY"}\n')
    app.run(host='0.0.0.0', port=PORT, debug=False)