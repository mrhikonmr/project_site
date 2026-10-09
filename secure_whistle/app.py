import io, os, secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, abort, flash, send_file, g)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet

BASE = os.path.dirname(os.path.abspath(__file__))
INST = os.path.join(BASE, 'instance')
UPLOADS = os.path.join(INST, 'uploads')          # вне static -> не отдаётся и не исполняется
os.makedirs(UPLOADS, exist_ok=True)

def load_key(name, gen):
    p = os.path.join(INST, name)
    if not os.path.exists(p):
        with open(p, 'wb') as f:
            f.write(gen())
        os.chmod(p, 0o600)
    with open(p, 'rb') as f:
        return f.read()

app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_key('secret.key', lambda: secrets.token_hex(32).encode()).decode(),
    SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(INST, 'app.db'),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get('INSECURE_DEV') != '1',
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),   # срок жизни сессии
    MAX_CONTENT_LENGTH=6 * 1024 * 1024,
)
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=['200/hour'], storage_uri='memory://')
ph = PasswordHasher()                                    # Argon2id
fernet = Fernet(load_key('fernet.key', Fernet.generate_key))   # AES-128-CBC + HMAC

ROLES = ('user', 'manager', 'admin')
STATUSES = {'new': 'Новое', 'in_review': 'В работе', 'resolved': 'Решено', 'rejected': 'Отклонено'}
ALLOWED = {'png': b'\x89PNG\r\n\x1a\n', 'jpg': b'\xff\xd8\xff', 'jpeg': b'\xff\xd8\xff', 'pdf': b'%PDF-'}

enc = lambda s: fernet.encrypt(s.encode()).decode()
dec = lambda t: fernet.decrypt(t.encode()).decode()

# ---------- Модели (ORM -> параметризованные запросы, SQLi исключён) ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    pw_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')
    active = db.Column(db.Boolean, default=True)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(32), unique=True, nullable=False)   # случайный публичный ID
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.Text, nullable=False)                     # зашифровано
    body = db.Column(db.Text, nullable=False)                      # зашифровано
    status = db.Column(db.String(12), default='new')
    created = db.Column(db.DateTime, default=datetime.utcnow)
    files = db.relationship('Attachment', backref='report', cascade='all,delete')
    messages = db.relationship('Message', backref='report', order_by='Message.id')

class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)
    stored = db.Column(db.String(64), nullable=False)
    ext = db.Column(db.String(5), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)
    from_manager = db.Column(db.Boolean, default=False)
    body = db.Column(db.Text, nullable=False)                      # зашифровано
    created = db.Column(db.DateTime, default=datetime.utcnow)

class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.Column(db.String(32))
    action = db.Column(db.String(40))
    target = db.Column(db.String(40))
    ip = db.Column(db.String(45))

def audit(action, target='', user=None):
    u = user or (g.user.username if getattr(g, 'user', None) else '-')
    db.session.add(Audit(user=u, action=action, target=target, ip=request.remote_addr))
    db.session.commit()

# ---------- Аутентификация и контроль доступа ----------
@app.before_request
def load_user():
    g.user = None
    uid = session.get('uid')
    if uid:
        u = db.session.get(User, uid)
        if u and u.active:
            g.user = u
        else:
            session.clear()

def roles_required(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if not g.user:
                return redirect(url_for('login'))
            if g.user.role not in roles:
                abort(403)
            return f(*a, **kw)
        return wrapper
    return deco

def get_report_or_404(code):
    """Единая точка проверки IDOR: автор ИЛИ manager. Иначе 404 (не раскрываем существование)."""
    r = Report.query.filter_by(code=code).first()
    if not r or not g.user:
        abort(404)
    if g.user.role == 'manager' or (g.user.role == 'user' and r.author_id == g.user.id):
        return r
    abort(404)

@app.after_request
def headers(resp):
    resp.headers['Content-Security-Policy'] = "default-src 'self'; frame-ancestors 'none'; form-action 'self'"
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['Cache-Control'] = 'no-store'
    return resp

# ---------- Маршруты ----------
@app.route('/')
def index():
    if not g.user:
        return redirect(url_for('login'))
    return redirect(url_for('admin' if g.user.role == 'admin' else 'reports'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit('5/hour', methods=['POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('username', '').strip()
        pw = request.form.get('password', '')
        ok = (3 <= len(name) <= 32 and name.replace('_', '').isalnum()
              and len(pw) >= 10 and any(c.isdigit() for c in pw) and any(c.isalpha() for c in pw))
        if not ok:
            flash('Логин: 3-32 символа (буквы/цифры/_). Пароль: от 10 символов, буквы и цифры.')
        elif User.query.filter_by(username=name).first():
            flash('Это имя занято.')
        else:
            db.session.add(User(username=name, pw_hash=ph.hash(pw), role='user'))   # роль только user
            db.session.commit()
            audit('register', name, user=name)
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('5/minute', methods=['POST'])      # Rate Limiting от брутфорса
def login():
    if request.method == 'POST':
        name = request.form.get('username', '')[:32]
        u = User.query.filter_by(username=name).first()
        good = False
        if u and u.active:
            try:
                good = ph.verify(u.pw_hash, request.form.get('password', ''))
            except VerifyMismatchError:
                good = False
        else:
            try: ph.verify(ph.hash('dummy'), 'x')      # выравниваем время ответа
            except VerifyMismatchError: pass
        if good:
            session.clear()                            # защита от session fixation
            session['uid'] = u.id
            session.permanent = True
            audit('login', u.username, user=u.username)
            return redirect(url_for('admin' if u.role == 'admin' else 'reports'))
        audit('login_failed', name, user=name)
        flash('Неверный логин или пароль.')
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    if g.user: audit('logout')
    session.clear()
    return redirect(url_for('login'))

@app.route('/reports')
@roles_required('user', 'manager')
def reports():
    q = Report.query.order_by(Report.created.desc())
    if g.user.role == 'user':
        q = q.filter_by(author_id=g.user.id)
    items = [(r, dec(r.title)) for r in q.all()]
    return render_template('reports.html', items=items, statuses=STATUSES)

def validate_file(f):
    """Проверка расширения + magic bytes + совпадение типа. Возвращает (ext, data)."""
    name = (f.filename or '').lower()
    ext = name.rsplit('.', 1)[-1] if '.' in name else ''
    if ext not in ALLOWED:
        raise ValueError('Разрешены только PNG, JPG, PDF.')
    data = f.read()
    if not data or not data.startswith(ALLOWED[ext]):
        raise ValueError('Содержимое файла не соответствует расширению.')
    return ext, data

@app.route('/reports/new', methods=['GET', 'POST'])
@roles_required('user')
@limiter.limit('10/hour', methods=['POST'])
def new_report():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        body = request.form.get('body', '').strip()
        files = [f for f in request.files.getlist('files') if f.filename][:3]
        if not (3 <= len(title) <= 120 and 10 <= len(body) <= 5000):
            flash('Тема: 3-120 символов, текст: 10-5000 символов.')
            return render_template('new.html')
        try:
            checked = [validate_file(f) for f in files]
        except ValueError as e:
            flash(str(e)); return render_template('new.html')
        r = Report(code=secrets.token_urlsafe(16), author_id=g.user.id, title=enc(title), body=enc(body))
        db.session.add(r); db.session.flush()
        for ext, data in checked:
            stored = secrets.token_hex(16)                 # случайное имя, исходное не используется
            with open(os.path.join(UPLOADS, stored), 'wb') as fh:
                fh.write(fernet.encrypt(data))             # шифрование файла на диске
            db.session.add(Attachment(report_id=r.id, stored=stored, ext=ext))
        db.session.commit()
        audit('report_create', r.code)
        flash('Обращение отправлено. Сохраните код: ' + r.code)
        return redirect(url_for('view_report', code=r.code))
    return render_template('new.html')

@app.route('/reports/<code>', methods=['GET', 'POST'])
@roles_required('user', 'manager')
def view_report(code):
    r = get_report_or_404(code)
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'status' and g.user.role == 'manager':
            st = request.form.get('status')
            if st in STATUSES:
                r.status = st; db.session.commit(); audit('status_' + st, r.code)
        elif action == 'message':
            text = request.form.get('message', '').strip()
            if 1 <= len(text) <= 2000:
                db.session.add(Message(report_id=r.id, from_manager=(g.user.role == 'manager'), body=enc(text)))
                db.session.commit(); audit('message', r.code)
            else:
                flash('Сообщение: 1-2000 символов.')
        return redirect(url_for('view_report', code=code))
    audit('report_view', r.code)
    msgs = [(m, dec(m.body)) for m in r.messages]
    return render_template('report.html', r=r, title=dec(r.title), body=dec(r.body),
                           msgs=msgs, statuses=STATUSES)

@app.route('/files/<int:fid>')
@roles_required('user', 'manager')
def download(fid):
    a = db.session.get(Attachment, fid) or abort(404)
    get_report_or_404(a.report.code)                       # та же проверка доступа
    with open(os.path.join(UPLOADS, a.stored), 'rb') as fh:
        data = fernet.decrypt(fh.read())
    audit('file_download', a.report.code)
    return send_file(io.BytesIO(data), as_attachment=True, download_name=f'attachment_{a.id}.{a.ext}',
                     mimetype='application/octet-stream')

@app.route('/admin')
@roles_required('admin')
def admin():
    return render_template('admin.html', users=User.query.order_by(User.id).all(),
                           logs=Audit.query.order_by(Audit.id.desc()).limit(100).all(), roles=ROLES)

@app.route('/admin/users', methods=['POST'])
@roles_required('admin')
def admin_create():
    name, pw, role = request.form.get('username', '').strip(), request.form.get('password', ''), request.form.get('role')
    if role in ('manager', 'admin') and 3 <= len(name) <= 32 and name.replace('_', '').isalnum() \
            and len(pw) >= 10 and not User.query.filter_by(username=name).first():
        db.session.add(User(username=name, pw_hash=ph.hash(pw), role=role)); db.session.commit()
        audit('user_create', name)
    else:
        flash('Неверные данные или имя занято.')
    return redirect(url_for('admin'))

@app.route('/admin/users/<int:uid>/toggle', methods=['POST'])
@roles_required('admin')
def admin_toggle(uid):
    u = db.session.get(User, uid) or abort(404)
    if u.id != g.user.id:
        u.active = not u.active; db.session.commit(); audit('user_toggle', u.username)
    return redirect(url_for('admin'))

# ---------- Обработка ошибок без stack trace ----------
MSG = {400: 'Некорректный запрос или истёк CSRF-токен.', 403: 'Доступ запрещён.', 404: 'Не найдено.',
       413: 'Файл слишком большой.', 429: 'Слишком много запросов. Подождите.', 500: 'Внутренняя ошибка.'}
for code in MSG:
    app.register_error_handler(code, lambda e, c=code: (render_template('error.html', msg=MSG[c], code=c), c))

@app.cli.command('init')
def init():
    """flask --app app init  -> создаёт БД и admin (пароль печатается один раз)."""
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        pw = secrets.token_urlsafe(12)
        db.session.add(User(username='admin', pw_hash=ph.hash(pw), role='admin')); db.session.commit()
        print('admin / ' + pw)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=False)     # debug=False: нет интерактивного отладчика/трассировок
