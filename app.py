import os, sqlite3, secrets, argparse
from datetime import datetime
from functools import wraps
from pathlib import Path
from flask import Flask, request, redirect, session, jsonify, send_from_directory, render_template, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

BASE = Path(__file__).resolve().parent
DB = BASE / 'database.db'
UPLOADS = BASE / 'uploads'
UPLOADS.mkdir(exist_ok=True)
load_dotenv(BASE / '.env')

app = Flask(__name__, template_folder=str(BASE), static_folder=str(BASE), static_url_path='')
app.config.update(SECRET_KEY=os.getenv('SECRET_KEY') or secrets.token_hex(32), MAX_CONTENT_LENGTH=8*1024*1024)
ALLOWED = {'pdf','jpg','jpeg','png'}

SCHEMA = '''
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, unit_no INTEGER UNIQUE, password_hash TEXT, mobile TEXT, role TEXT NOT NULL DEFAULT 'RESIDENT', active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS charges(id INTEGER PRIMARY KEY AUTOINCREMENT, unit_no INTEGER NOT NULL, amount INTEGER NOT NULL, period TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'پرداخت نشده', created_at TEXT NOT NULL, UNIQUE(unit_no,period));
CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY AUTOINCREMENT, charge_id INTEGER NOT NULL, unit_no INTEGER NOT NULL, amount INTEGER NOT NULL, paid_at TEXT NOT NULL, description TEXT, status TEXT NOT NULL DEFAULT 'در انتظار تأیید', rejection_reason TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS receipts(id INTEGER PRIMARY KEY AUTOINCREMENT, payment_id INTEGER NOT NULL, filename TEXT NOT NULL, original_name TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS bills(id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, amount INTEGER NOT NULL, bill_date TEXT NOT NULL, period TEXT, filename TEXT, original_name TEXT, description TEXT, created_at TEXT NOT NULL, author_id INTEGER);
CREATE TABLE IF NOT EXISTS announcements(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, body TEXT NOT NULL, published INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, author_id INTEGER);
CREATE TABLE IF NOT EXISTS maintenance_requests(id INTEGER PRIMARY KEY AUTOINCREMENT, unit_no INTEGER NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, issue_type TEXT, status TEXT NOT NULL DEFAULT 'جدید', manager_note TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS outages(id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, outage_date TEXT NOT NULL, start_time TEXT, end_time TEXT, description TEXT, status TEXT NOT NULL DEFAULT 'فعال', created_at TEXT NOT NULL, author_id INTEGER);
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, read INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS manager_history(id INTEGER PRIMARY KEY AUTOINCREMENT, previous_unit INTEGER, new_unit INTEGER, started_at TEXT NOT NULL, ended_at TEXT, changed_by INTEGER);
CREATE TABLE IF NOT EXISTS activity_logs(id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER, action TEXT NOT NULL, details TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS push_subscriptions(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, endpoint TEXT NOT NULL UNIQUE, subscription_json TEXT NOT NULL, created_at TEXT NOT NULL);
'''

def now(): return datetime.now().isoformat(timespec='seconds')
def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    return c

def init_db():
    c=db(); c.executescript(SCHEMA)
    for n in range(1,9):
        c.execute('INSERT OR IGNORE INTO users(unit_no,password_hash,mobile,role,active,created_at) VALUES(?,?,?,?,?,?)',(n,generate_password_hash(secrets.token_urlsafe(16)), '', 'RESIDENT',1,now()))
    c.commit(); c.close()

def log(action, details=''):
    c=db(); c.execute('INSERT INTO activity_logs(actor_id,action,details,created_at) VALUES(?,?,?,?)',(session.get('user_id'),action,details,now())); c.commit(); c.close()

def csrf_token():
    if 'csrf' not in session: session['csrf']=secrets.token_urlsafe(32)
    return session['csrf']
app.jinja_env.globals['csrf_token']=csrf_token

def require_csrf():
    if request.method in ('POST','PUT','PATCH','DELETE') and request.form.get('csrf') != session.get('csrf'): abort(400)

def auth_required(role=None):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a,**kw):
            if not session.get('user_id'): return redirect('/super-admin/login' if session.get('login_kind')=='super' else '/login')
            if role and session.get('role') not in role: abort(403)
            return fn(*a,**kw)
        return wrapper
    return deco

@app.before_request
def before():
    require_csrf()
    if request.endpoint not in ('login','super_login','static','health') and request.method=='GET': csrf_token()

def user_row():
    if not session.get('user_id'): return None
    c=db(); u=c.execute('SELECT * FROM users WHERE id=?',(session['user_id'],)).fetchone(); c.close(); return u

def setup_ready(): return bool(os.getenv('SUPER_ADMIN_PASSWORD'))

@app.get('/health')
def health(): return jsonify(ok=True, app='Building206')

@app.get('/')
def home(): return redirect('/dashboard' if session.get('user_id') else '/login')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        unit=request.form.get('unit','').strip(); password=request.form.get('password','')
        if not unit.isdigit() or not 1 <= int(unit) <= 8: return render_template('login.html',error='شماره واحد نامعتبر است.')
        c=db(); u=c.execute('SELECT * FROM users WHERE unit_no=?',(int(unit),)).fetchone(); c.close()
        if not u or not u['active'] or not check_password_hash(u['password_hash'],password):
            return render_template('login.html',error='شماره واحد یا رمز عبور صحیح نیست.')
        session.clear(); session.update(user_id=u['id'],unit_no=u['unit_no'],role=u['role'],login_kind='unit',csrf=secrets.token_urlsafe(32)); log('login',f'unit={u["unit_no"]}')
        return redirect('/dashboard')
    return render_template('login.html',error=None)

@app.route('/super-admin/login', methods=['GET','POST'])
def super_login():
    if request.method=='POST':
        if not setup_ready() or not check_password_hash(generate_password_hash(os.getenv('SUPER_ADMIN_PASSWORD')), request.form.get('password','')):
            # comparison is intentionally against env; no secret is sent to client
            return render_template('super_admin_login.html',error='رمز عبور صحیح نیست.')
        session.clear(); session.update(user_id=0,role='SUPER_ADMIN',login_kind='super',csrf=secrets.token_urlsafe(32)); return redirect('/super-admin')
    return render_template('super_admin_login.html',error=None)

# The super-admin is represented by user_id=0; no password is persisted in SQLite.
def super_required(fn):
    @wraps(fn)
    def w(*a,**kw):
        if session.get('role')!='SUPER_ADMIN': abort(403)
        return fn(*a,**kw)
    return w

@app.get('/dashboard')
@auth_required(('RESIDENT','ADMIN'))
def dashboard():
    return render_template('dashboard.html', user=user_row(), role=session['role'])

@app.get('/admin')
@auth_required(('ADMIN','SUPER_ADMIN'))
def admin(): return render_template('admin.html', user=user_row(), role=session['role'])

@app.get('/super-admin')
@super_required
def super_admin(): return render_template('super_admin.html')

@app.post('/logout')
def logout(): session.clear(); return redirect('/login')

@app.get('/api/me')
@auth_required()
def me():
    u=user_row(); return jsonify(id=u['id'],unit=u['unit_no'],mobile=u['mobile'],role=u['role'])

@app.get('/api/dashboard')
@auth_required(('RESIDENT','ADMIN'))
def api_dashboard():
    unit=session.get('unit_no'); c=db()
    charges=c.execute('SELECT * FROM charges WHERE unit_no=? ORDER BY id DESC LIMIT 12',(unit,)).fetchall()
    anns=c.execute('SELECT * FROM announcements WHERE published=1 ORDER BY id DESC LIMIT 8').fetchall()
    reqs=c.execute('SELECT * FROM maintenance_requests WHERE unit_no=? ORDER BY id DESC LIMIT 8',(unit,)).fetchall()
    bills=c.execute('SELECT id,kind,amount,bill_date,period,description,created_at FROM bills ORDER BY id DESC LIMIT 8').fetchall()
    outages=c.execute('SELECT * FROM outages WHERE status="فعال" ORDER BY id DESC').fetchall()
    notifs=c.execute('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 12',(session['user_id'],)).fetchall() if session['user_id'] else []
    c.close(); return jsonify(charges=[dict(x) for x in charges],announcements=[dict(x) for x in anns],requests=[dict(x) for x in reqs],bills=[dict(x) for x in bills],outages=[dict(x) for x in outages],notifications=[dict(x) for x in notifs])

@app.post('/api/password')
@auth_required(('RESIDENT','ADMIN'))
def change_own_password():
    old=request.form.get('old_password',''); new=request.form.get('new_password','')
    if len(new)<8: return jsonify(error='رمز جدید باید حداقل ۸ کاراکتر باشد.'),400
    c=db(); u=c.execute('SELECT password_hash FROM users WHERE id=?',(session['user_id'],)).fetchone()
    if not check_password_hash(u['password_hash'],old): c.close(); return jsonify(error='رمز فعلی صحیح نیست.'),400
    c.execute('UPDATE users SET password_hash=? WHERE id=?',(generate_password_hash(new),session['user_id'])); c.commit(); c.close(); log('password_change'); return jsonify(ok=True)

@app.post('/api/requests')
@auth_required(('RESIDENT','ADMIN'))
def create_request():
    title=request.form.get('title','').strip(); body=request.form.get('body','').strip(); issue=request.form.get('issue_type','').strip()
    if not title or not body: return jsonify(error='عنوان و توضیحات الزامی است.'),400
    t=now(); c=db(); c.execute('INSERT INTO maintenance_requests(unit_no,title,body,issue_type,created_at,updated_at) VALUES(?,?,?,?,?,?)',(session['unit_no'],title,body,issue,t,t)); c.commit(); c.close(); log('maintenance_create',title); return jsonify(ok=True)

@app.post('/api/payments')
@auth_required(('RESIDENT','ADMIN'))
def pay():
    charge_id=request.form.get('charge_id'); amount=request.form.get('amount'); paid_at=request.form.get('paid_at') or now()[:10]
    if not charge_id or not amount.isdigit(): return jsonify(error='اطلاعات پرداخت نامعتبر است.'),400
    c=db(); ch=c.execute('SELECT * FROM charges WHERE id=? AND unit_no=?',(charge_id,session['unit_no'])).fetchone()
    if not ch: c.close(); return jsonify(error='شارژ پیدا نشد.'),404
    pid=c.execute('INSERT INTO payments(charge_id,unit_no,amount,paid_at,description,status,created_at) VALUES(?,?,?,?,?,?,?)',(ch['id'],session['unit_no'],int(amount),paid_at,request.form.get('description',''),'در انتظار تأیید',now())).lastrowid
    c.execute('UPDATE charges SET status=? WHERE id=?','در انتظار تأیید',ch['id']); c.commit()
    f=request.files.get('receipt')
    if f and f.filename:
        ext=Path(secure_filename(f.filename)).suffix.lower().lstrip('.')
        if ext not in ALLOWED: c.close(); return jsonify(error='فرمت فایل مجاز نیست.'),400
        name=secrets.token_hex(16)+'.'+ext; f.save(UPLOADS/name); c.execute('INSERT INTO receipts(payment_id,filename,original_name,created_at) VALUES(?,?,?,?)',(pid,name,secure_filename(f.filename),now())); c.commit()
    c.close(); log('payment_submit',f'payment={pid}'); return jsonify(ok=True)

@app.get('/api/notifications/read/<int:nid>')
@auth_required(('RESIDENT','ADMIN'))
def read_notification(nid):
    c=db(); c.execute('UPDATE notifications SET read=1 WHERE id=? AND user_id=?',(nid,session['user_id'])); c.commit(); c.close(); return jsonify(ok=True)

@app.get('/private/receipt/<int:rid>')
@auth_required(('RESIDENT','ADMIN','SUPER_ADMIN'))
def receipt(rid):
    c=db(); r=c.execute('SELECT r.*,p.unit_no FROM receipts r JOIN payments p ON p.id=r.payment_id WHERE r.id=?',(rid,)).fetchone(); c.close()
    if not r: abort(404)
    if session['role']=='RESIDENT' and r['unit_no']!=session['unit_no']: abort(403)
    return send_from_directory(UPLOADS,r['filename'],as_attachment=False)

# Admin/Super-admin API
@app.get('/api/admin/overview')
@auth_required(('ADMIN','SUPER_ADMIN'))
def overview():
    c=db(); data={
      'units':[dict(x) for x in c.execute('SELECT id,unit_no,mobile,role,active FROM users ORDER BY unit_no') .fetchall()],
      'pending':[dict(x) for x in c.execute('SELECT p.*,r.id receipt_id FROM payments p LEFT JOIN receipts r ON r.payment_id=p.id WHERE p.status="در انتظار تأیید" ORDER BY p.id DESC').fetchall()],
      'requests':[dict(x) for x in c.execute('SELECT * FROM maintenance_requests ORDER BY id DESC LIMIT 30').fetchall()],
      'charges':[dict(x) for x in c.execute('SELECT * FROM charges ORDER BY period DESC,unit_no').fetchall()],
      'bills':[dict(x) for x in c.execute('SELECT * FROM bills ORDER BY id DESC LIMIT 30').fetchall()],
      'announcements':[dict(x) for x in c.execute('SELECT * FROM announcements ORDER BY id DESC LIMIT 30').fetchall()],
      'outages':[dict(x) for x in c.execute('SELECT * FROM outages ORDER BY id DESC LIMIT 30').fetchall()]}; c.close(); return jsonify(data)

def manager_or_super(fn): return auth_required(('ADMIN','SUPER_ADMIN'))(fn)

@app.post('/api/admin/charges')
@manager_or_super
def create_charge():
    unit=request.form.get('unit'); amount=request.form.get('amount'); period=request.form.get('period')
    if not unit or not amount or not amount.isdigit() or not period: return jsonify(error='اطلاعات ناقص است.'),400
    c=db()
    try: c.execute('INSERT INTO charges(unit_no,amount,period,created_at) VALUES(?,?,?,?)',(int(unit),int(amount),period,now())); c.commit()
    except sqlite3.IntegrityError: c.close(); return jsonify(error='برای این واحد و دوره قبلاً شارژ ثبت شده است.'),409
    c.close(); log('charge_create',f'unit={unit},period={period}'); return jsonify(ok=True)

@app.post('/api/admin/payments/<int:pid>/review')
@manager_or_super
def review_payment(pid):
    status=request.form.get('status'); reason=request.form.get('reason','')
    if status not in ('تأیید شده','رد شده'): return jsonify(error='وضعیت نامعتبر است.'),400
    c=db(); p=c.execute('SELECT * FROM payments WHERE id=?',(pid,)).fetchone()
    if not p: c.close(); return jsonify(error='پرداخت پیدا نشد.'),404
    c.execute('UPDATE payments SET status=?,rejection_reason=? WHERE id=?',(status,reason,pid)); c.execute('UPDATE charges SET status=? WHERE id=?',(status,p['charge_id'])); c.commit(); c.close(); log('payment_review',f'payment={pid}:{status}'); return jsonify(ok=True)

@app.post('/api/admin/requests/<int:rid>')
@manager_or_super
def update_request(rid):
    status=request.form.get('status'); note=request.form.get('manager_note','')
    allowed=('جدید','در حال بررسی','در حال انجام','انجام شد','رد شد')
    if status not in allowed: return jsonify(error='وضعیت نامعتبر است.'),400
    c=db(); c.execute('UPDATE maintenance_requests SET status=?,manager_note=?,updated_at=? WHERE id=?',(status,note,now(),rid)); c.commit(); c.close(); log('maintenance_update',f'id={rid}:{status}'); return jsonify(ok=True)

@app.post('/api/admin/announcement')
@manager_or_super
def announcement():
    title=request.form.get('title','').strip(); body=request.form.get('body','').strip()
    if not title or not body: return jsonify(error='عنوان و متن الزامی است.'),400
    c=db(); aid=c.execute('INSERT INTO announcements(title,body,published,created_at,author_id) VALUES(?,?,?,?,?)',(title,body,1,now(),session.get('user_id'))).lastrowid
    users=c.execute('SELECT id FROM users WHERE active=1').fetchall()
    for u in users: c.execute('INSERT INTO notifications(user_id,title,body,created_at) VALUES(?,?,?,?)',(u['id'],title,body,now()))
    c.commit(); c.close(); log('announcement_create',f'id={aid}'); return jsonify(ok=True)

@app.post('/api/admin/outage')
@manager_or_super
def outage():
    kind=request.form.get('kind'); date=request.form.get('date');
    if kind not in ('آب','برق','گاز') or not date: return jsonify(error='اطلاعات نامعتبر است.'),400
    c=db(); c.execute('INSERT INTO outages(kind,outage_date,start_time,end_time,description,status,created_at,author_id) VALUES(?,?,?,?,?,?,?,?)',(kind,date,request.form.get('start_time'),request.form.get('end_time'),request.form.get('description',''),request.form.get('status','فعال'),now(),session.get('user_id'))); c.commit(); c.close(); return jsonify(ok=True)

@app.post('/api/admin/bill')
@manager_or_super
def bill():
    kind=request.form.get('kind'); amount=request.form.get('amount'); date=request.form.get('date')
    if kind not in ('آب','برق','گاز','سایر') or not amount or not amount.isdigit() or not date: return jsonify(error='اطلاعات قبض نامعتبر است.'),400
    f=request.files.get('file'); filename=None; original=None
    if f and f.filename:
        ext=Path(secure_filename(f.filename)).suffix.lower().lstrip('.')
        if ext not in ALLOWED: return jsonify(error='فرمت فایل مجاز نیست.'),400
        filename=secrets.token_hex(16)+'.'+ext; original=secure_filename(f.filename); f.save(UPLOADS/filename)
    c=db(); c.execute('INSERT INTO bills(kind,amount,bill_date,period,filename,original_name,description,created_at,author_id) VALUES(?,?,?,?,?,?,?,?,?)',(kind,int(amount),date,request.form.get('period'),filename,original,request.form.get('description',''),now(),session.get('user_id'))); c.commit(); c.close(); return jsonify(ok=True)

@app.post('/api/super/units/<int:unit>/password')
@super_required
def unit_password(unit):
    new=request.form.get('new_password','')
    if unit not in range(1,9) or len(new)<8: return jsonify(error='واحد یا رمز نامعتبر است.'),400
    c=db(); c.execute('UPDATE users SET password_hash=? WHERE unit_no=?',(generate_password_hash(new),unit)); c.commit(); c.close(); log('unit_password_change',f'unit={unit}'); return jsonify(ok=True)

@app.post('/api/super/units/<int:unit>/profile')
@super_required
def unit_profile(unit):
    mobile=request.form.get('mobile','').strip(); active=1 if request.form.get('active')=='1' else 0
    c=db(); c.execute('UPDATE users SET mobile=?,active=? WHERE unit_no=?',(mobile,active,unit)); c.commit(); c.close(); log('unit_profile_change',f'unit={unit}'); return jsonify(ok=True)

@app.post('/api/super/manager')
@super_required
def set_manager():
    new=request.form.get('unit')
    if not new or int(new) not in range(1,9): return jsonify(error='واحد نامعتبر است.'),400
    new=int(new); c=db(); old=c.execute('SELECT unit_no FROM users WHERE role="ADMIN"').fetchone(); old_unit=old['unit_no'] if old else None
    if old_unit==new: c.close(); return jsonify(ok=True)
    if old_unit: c.execute('UPDATE users SET role="RESIDENT" WHERE unit_no=?',(old_unit,)); c.execute('UPDATE manager_history SET ended_at=? WHERE new_unit=? AND ended_at IS NULL',(now(),old_unit))
    c.execute('UPDATE users SET role="ADMIN" WHERE unit_no=?',(new,)); c.execute('INSERT INTO manager_history(previous_unit,new_unit,started_at,changed_by) VALUES(?,?,?,?)',(old_unit,new,now(),None)); c.commit(); c.close(); log('manager_change',f'{old_unit}->{new}'); return jsonify(ok=True)

@app.post('/api/super/charge')
@super_required
def super_charge(): return create_charge()

@app.get('/private/bill/<int:bid>')
@auth_required(('RESIDENT','ADMIN','SUPER_ADMIN'))
def private_bill(bid):
    c=db(); b=c.execute('SELECT filename FROM bills WHERE id=?',(bid,)).fetchone(); c.close()
    if not b or not b['filename']: abort(404)
    return send_from_directory(UPLOADS,b['filename'])

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--init',action='store_true'); parser.add_argument('--host',default='127.0.0.1'); parser.add_argument('--port',type=int,default=int(os.getenv('PORT','5000'))); args=parser.parse_args()
    init_db()
    if args.init:
        print('Database initialized. Set SUPER_ADMIN_PASSWORD in .env before using /super-admin/login.')
    else: app.run(host=args.host,port=args.port,debug=False)
