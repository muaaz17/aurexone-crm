from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import bcrypt
import jwt
import uuid
from datetime import datetime, timedelta
from functools import wraps
import os

app = Flask(__name__)
CORS(app)

SECRET_KEY = "aurexone_crm_secret_2024"
DB_PATH = "crm.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'team_member',
        department TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS leads (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        company TEXT,
        source TEXT,
        status TEXT DEFAULT 'new',
        value REAL DEFAULT 0,
        assigned_to TEXT,
        notes TEXT,
        created_by TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'todo',
        priority TEXT DEFAULT 'medium',
        assigned_to TEXT,
        related_lead TEXT,
        due_date TEXT,
        created_by TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS activities (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        description TEXT,
        user_id TEXT,
        related_id TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    # Create default super admin
    existing = c.execute("SELECT id FROM users WHERE email = 'admin@aurexone.com'").fetchone()
    if not existing:
        pw = bcrypt.hashpw("Admin@123".encode(), bcrypt.gensalt()).decode()
        c.execute("INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)",
                  (str(uuid.uuid4()), "Moaz Ur Rehman", "admin@aurexone.com", pw, "super_admin"))

    conn.commit()
    conn.close()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token missing'}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            conn = get_db()
            user = conn.execute("SELECT * FROM users WHERE id = ? AND is_active = 1", (data['id'],)).fetchone()
            conn.close()
            if not user:
                return jsonify({'error': 'User not found'}), 401
            request.user = dict(user)
        except:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if request.user['role'] not in roles:
                return jsonify({'error': 'Unauthorized'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# AUTH
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ? AND is_active = 1", (data['email'],)).fetchone()
    conn.close()
    if not user or not bcrypt.checkpw(data['password'].encode(), user['password'].encode()):
        return jsonify({'error': 'Invalid credentials'}), 401
    token = jwt.encode({'id': user['id'], 'exp': datetime.utcnow() + timedelta(days=7)}, SECRET_KEY)
    return jsonify({'token': token, 'user': {k: user[k] for k in user.keys() if k != 'password'}})

@app.route('/api/auth/me', methods=['GET'])
@token_required
def me():
    return jsonify({k: v for k, v in request.user.items() if k != 'password'})

# USERS
@app.route('/api/users', methods=['GET'])
@token_required
def get_users():
    conn = get_db()
    users = conn.execute("SELECT id, name, email, role, department, is_active, created_at FROM users ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route('/api/users', methods=['POST'])
@token_required
def create_user():
    if request.user['role'] not in ['super_admin', 'admin']:
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.json
    pw = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt()).decode()
    uid = str(uuid.uuid4())
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (id, name, email, password, role, department) VALUES (?, ?, ?, ?, ?, ?)",
                     (uid, data['name'], data['email'], pw, data.get('role', 'team_member'), data.get('department', '')))
        conn.commit()
        log_activity(conn, 'user_created', f"User {data['name']} created", request.user['id'], uid)
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Email already exists'}), 400
    conn.close()
    return jsonify({'id': uid, 'message': 'User created'}), 201

@app.route('/api/users/<uid>', methods=['PUT'])
@token_required
def update_user(uid):
    if request.user['role'] not in ['super_admin', 'admin'] and request.user['id'] != uid:
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.json
    conn = get_db()
    conn.execute("UPDATE users SET name=?, role=?, department=?, is_active=? WHERE id=?",
                 (data['name'], data['role'], data.get('department', ''), data.get('is_active', 1), uid))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Updated'})

@app.route('/api/users/<uid>', methods=['DELETE'])
@token_required
def delete_user(uid):
    if request.user['role'] != 'super_admin':
        return jsonify({'error': 'Unauthorized'}), 403
    conn = get_db()
    conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (uid,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Deactivated'})

# LEADS
@app.route('/api/leads', methods=['GET'])
@token_required
def get_leads():
    conn = get_db()
    if request.user['role'] == 'team_member':
        leads = conn.execute("SELECT l.*, u.name as assigned_name FROM leads l LEFT JOIN users u ON l.assigned_to = u.id WHERE l.assigned_to = ? ORDER BY l.created_at DESC", (request.user['id'],)).fetchall()
    else:
        leads = conn.execute("SELECT l.*, u.name as assigned_name FROM leads l LEFT JOIN users u ON l.assigned_to = u.id ORDER BY l.created_at DESC").fetchall()
    conn.close()
    return jsonify([dict(l) for l in leads])

@app.route('/api/leads', methods=['POST'])
@token_required
def create_lead():
    data = request.json
    lid = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    conn = get_db()
    conn.execute("INSERT INTO leads (id, name, email, phone, company, source, status, value, assigned_to, notes, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 (lid, data['name'], data.get('email',''), data.get('phone',''), data.get('company',''),
                  data.get('source',''), data.get('status','new'), data.get('value',0),
                  data.get('assigned_to'), data.get('notes',''), request.user['id'], now, now))
    log_activity(conn, 'lead_created', f"Lead {data['name']} added", request.user['id'], lid)
    conn.commit()
    conn.close()
    return jsonify({'id': lid, 'message': 'Lead created'}), 201

@app.route('/api/leads/<lid>', methods=['PUT'])
@token_required
def update_lead(lid):
    data = request.json
    now = datetime.utcnow().isoformat()
    conn = get_db()
    conn.execute("UPDATE leads SET name=?, email=?, phone=?, company=?, source=?, status=?, value=?, assigned_to=?, notes=?, updated_at=? WHERE id=?",
                 (data['name'], data.get('email',''), data.get('phone',''), data.get('company',''),
                  data.get('source',''), data['status'], data.get('value',0),
                  data.get('assigned_to'), data.get('notes',''), now, lid))
    log_activity(conn, 'lead_updated', f"Lead updated to {data['status']}", request.user['id'], lid)
    conn.commit()
    conn.close()
    return jsonify({'message': 'Updated'})

@app.route('/api/leads/<lid>', methods=['DELETE'])
@token_required
def delete_lead(lid):
    if request.user['role'] not in ['super_admin', 'admin']:
        return jsonify({'error': 'Unauthorized'}), 403
    conn = get_db()
    conn.execute("DELETE FROM leads WHERE id = ?", (lid,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Deleted'})

# TASKS
@app.route('/api/tasks', methods=['GET'])
@token_required
def get_tasks():
    conn = get_db()
    if request.user['role'] == 'team_member':
        tasks = conn.execute("SELECT t.*, u.name as assigned_name FROM tasks t LEFT JOIN users u ON t.assigned_to = u.id WHERE t.assigned_to = ? ORDER BY t.created_at DESC", (request.user['id'],)).fetchall()
    else:
        tasks = conn.execute("SELECT t.*, u.name as assigned_name FROM tasks t LEFT JOIN users u ON t.assigned_to = u.id ORDER BY t.created_at DESC").fetchall()
    conn.close()
    return jsonify([dict(t) for t in tasks])

@app.route('/api/tasks', methods=['POST'])
@token_required
def create_task():
    data = request.json
    tid = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    conn = get_db()
    conn.execute("INSERT INTO tasks (id, title, description, status, priority, assigned_to, related_lead, due_date, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                 (tid, data['title'], data.get('description',''), data.get('status','todo'),
                  data.get('priority','medium'), data.get('assigned_to'), data.get('related_lead'),
                  data.get('due_date'), request.user['id'], now, now))
    log_activity(conn, 'task_created', f"Task '{data['title']}' created", request.user['id'], tid)
    conn.commit()
    conn.close()
    return jsonify({'id': tid, 'message': 'Task created'}), 201

@app.route('/api/tasks/<tid>', methods=['PUT'])
@token_required
def update_task(tid):
    data = request.json
    now = datetime.utcnow().isoformat()
    conn = get_db()
    conn.execute("UPDATE tasks SET title=?, description=?, status=?, priority=?, assigned_to=?, due_date=?, updated_at=? WHERE id=?",
                 (data['title'], data.get('description',''), data['status'], data.get('priority','medium'),
                  data.get('assigned_to'), data.get('due_date'), now, tid))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Updated'})

@app.route('/api/tasks/<tid>', methods=['DELETE'])
@token_required
def delete_task(tid):
    conn = get_db()
    conn.execute("DELETE FROM tasks WHERE id = ?", (tid,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Deleted'})

# DASHBOARD STATS
@app.route('/api/dashboard', methods=['GET'])
@token_required
def dashboard():
    conn = get_db()
    total_leads = conn.execute("SELECT COUNT(*) as c FROM leads").fetchone()['c']
    won_leads = conn.execute("SELECT COUNT(*) as c FROM leads WHERE status='won'").fetchone()['c']
    pipeline_value = conn.execute("SELECT COALESCE(SUM(value),0) as v FROM leads WHERE status NOT IN ('won','lost')").fetchone()['v']
    total_tasks = conn.execute("SELECT COUNT(*) as c FROM tasks").fetchone()['c']
    pending_tasks = conn.execute("SELECT COUNT(*) as c FROM tasks WHERE status != 'done'").fetchone()['c']
    total_team = conn.execute("SELECT COUNT(*) as c FROM users WHERE is_active=1").fetchone()['c']

    leads_by_status = conn.execute("SELECT status, COUNT(*) as count FROM leads GROUP BY status").fetchall()
    recent_activities = conn.execute("SELECT a.*, u.name as user_name FROM activities a LEFT JOIN users u ON a.user_id = u.id ORDER BY a.created_at DESC LIMIT 10").fetchall()

    conn.close()
    return jsonify({
        'stats': {
            'total_leads': total_leads,
            'won_leads': won_leads,
            'pipeline_value': pipeline_value,
            'total_tasks': total_tasks,
            'pending_tasks': pending_tasks,
            'total_team': total_team
        },
        'leads_by_status': [dict(l) for l in leads_by_status],
        'recent_activities': [dict(a) for a in recent_activities]
    })

def log_activity(conn, type, description, user_id, related_id=None):
    conn.execute("INSERT INTO activities (id, type, description, user_id, related_id) VALUES (?,?,?,?,?)",
                 (str(uuid.uuid4()), type, description, user_id, related_id))

if __name__ == '__main__':
    init_db()
    app.run(port=5000, debug=True)
