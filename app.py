import os, sqlite3, secrets, hashlib, hmac, json
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, session, g, send_from_directory

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "hpf_family.db")

app = Flask(__name__, static_folder=None)
app.secret_key = os.environ.get("HPF_SECRET_KEY")
if not app.secret_key and os.environ.get("FLASK_ENV") == "production":
    raise RuntimeError("HPF_SECRET_KEY must be configured in production.")
app.secret_key = app.secret_key or "dev-only-change-me"
app.permanent_session_lifetime = timedelta(days=7)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1"
)

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close(_):
    c = g.pop("db", None)
    if c:
        c.close()

def init_db():
    db().executescript("""
    CREATE TABLE IF NOT EXISTS members(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE,
        campus TEXT NOT NULL,
        hostel TEXT,
        department TEXT,
        level TEXT,
        gender TEXT,
        connection TEXT,
        service TEXT,
        story TEXT,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'member',
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS applications(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        campus TEXT,
        hostel TEXT,
        payload TEXT NOT NULL,
        status TEXT DEFAULT 'new',
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS announcements(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS programs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        date TEXT,
        time TEXT,
        venue TEXT,
        description TEXT,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS prayer_requests(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        member_id INTEGER,
        name TEXT NOT NULL,
        request TEXT NOT NULL,
        status TEXT DEFAULT 'open',
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS testimonies(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        member_id INTEGER,
        name TEXT NOT NULL,
        title TEXT NOT NULL,
        story TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TEXT NOT NULL
    );
    """)

def hp(p, s=None):
    s = s or secrets.token_bytes(16)
    return s.hex() + ":" + hashlib.pbkdf2_hmac("sha256", p.encode(), s, 210000).hex()

def check(p, stored):
    try:
        s, d = stored.split(":")
        calc = hashlib.pbkdf2_hmac("sha256", p.encode(), bytes.fromhex(s), 210000).hex()
        return hmac.compare_digest(calc, d)
    except:
        return False

def public(r):
    d = dict(r)
    d.pop("password_hash", None)
    return d

def auth(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("member_id"):
            return jsonify(error="Login required"), 401
        return f(*a, **k)
    return w

def admin(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("member_id"):
            return jsonify(error="Login required"), 401
        r = db().execute("SELECT role FROM members WHERE id=?", (session["member_id"],)).fetchone()
        if not r or r["role"] != "admin":
            return jsonify(error="Administrator access required"), 403
        return f(*a, **k)
    return w

@app.post("/api/register")
def register():
    d = request.get_json(force=True)
    for k in ("name", "phone", "campus", "connection", "password"):
        if not str(d.get(k, "")).strip():
            return jsonify(error=f"{k} is required"), 400
    if len(d["password"]) < 8:
        return jsonify(error="Password must be at least 8 characters"), 400
    try:
        c = db()
        cur = c.execute("""INSERT INTO members(
            name, phone, email, campus, hostel, department, level, gender,
            connection, service, story, password_hash, created_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            d["name"].strip(),
            d["phone"].strip(),
            d.get("email") or None,
            d["campus"],
            d.get("hostel", ""),
            d.get("department", ""),
            d.get("level", ""),
            d.get("gender", ""),
            d["connection"],
            d.get("service", ""),
            d.get("story", ""),
            hp(d["password"]),
            datetime.utcnow().isoformat()
        ))
        c.commit()
        session.permanent = True
        session["member_id"] = cur.lastrowid
        return jsonify(member=public(c.execute("SELECT * FROM members WHERE id=?", (cur.lastrowid,)).fetchone())), 201
    except sqlite3.IntegrityError:
        return jsonify(error="WhatsApp number or email already registered"), 409

@app.post("/api/login")
def login():
    d = request.get_json(force=True)
    ident = d.get("identity", "").strip()
    r = db().execute("SELECT * FROM members WHERE phone=? OR email=?", (ident, ident)).fetchone()
    if not r or not check(d.get("password", ""), r["password_hash"]):
        return jsonify(error="Invalid login details"), 401
    session.permanent = True
    session["member_id"] = r["id"]
    return jsonify(member=public(r))

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)

@app.get("/api/me")
@auth
def me():
    return jsonify(member=public(db().execute("SELECT * FROM members WHERE id=?", (session["member_id"],)).fetchone()))

@app.post("/api/applications")
def applications():
    d = request.get_json(force=True)
    kind = d.get("kind")
    if kind not in ("executive", "hostel"):
        return jsonify(error="Invalid application type"), 400
    c = db()
    cur = c.execute(
        "INSERT INTO applications(kind, name, phone, campus, hostel, payload, created_at) VALUES (?,?,?,?,?,?,?)",
        (kind, d.get("name"), d.get("phone"), d.get("campus", ""), d.get("hostel", ""), json.dumps(d, ensure_ascii=False), datetime.utcnow().isoformat())
    )
    c.commit()
    return jsonify(id=cur.lastrowid, status="new"), 201

@app.get("/api/announcements")
def announcements():
    return jsonify(items=[dict(r) for r in db().execute("SELECT * FROM announcements ORDER BY id DESC").fetchall()])

@app.get("/api/programs")
def programs():
    return jsonify(items=[dict(r) for r in db().execute("SELECT * FROM programs ORDER BY date ASC, id DESC").fetchall()])

@app.post("/api/prayer")
@auth
def prayer():
    d = request.get_json(force=True)
    if not d.get("request", "").strip():
        return jsonify(error="Prayer request is required"), 400
    c = db()
    c.execute(
        "INSERT INTO prayer_requests(member_id, name, request, created_at) VALUES (?,?,?,?)",
        (session["member_id"], d.get("name", "HPF Member"), d["request"], datetime.utcnow().isoformat())
    )
    c.commit()
    return jsonify(ok=True), 201

@app.post("/api/testimony")
@auth
def testimony():
    d = request.get_json(force=True)
    if not d.get("title") or not d.get("story"):
        return jsonify(error="Title and testimony are required"), 400
    c = db()
    c.execute(
        "INSERT INTO testimonies(member_id, name, title, story, created_at) VALUES (?,?,?,?,?)",
        (session["member_id"], d.get("name", "HPF Member"), d["title"], d["story"], datetime.utcnow().isoformat())
    )
    c.commit()
    return jsonify(ok=True), 201

@app.get("/api/admin/overview")
@admin
def overview():
    c = db()
    return jsonify(
        members=c.execute("SELECT COUNT(*) c FROM members").fetchone()["c"],
        applications=c.execute("SELECT COUNT(*) c FROM applications").fetchone()["c"],
        prayer_requests=c.execute("SELECT COUNT(*) c FROM prayer_requests").fetchone()["c"],
        testimonies=c.execute("SELECT COUNT(*) c FROM testimonies").fetchone()["c"]
    )

@app.get("/api/admin/members")
@admin
def members():
    return jsonify(members=[public(r) for r in db().execute("SELECT * FROM members ORDER BY id DESC").fetchall()])

@app.get("/api/admin/applications")
@admin
def apps():
    return jsonify(applications=[dict(r) for r in db().execute("SELECT * FROM applications ORDER BY id DESC").fetchall()])

@app.post("/api/admin/announcements")
@admin
def add_announcement():
    d = request.get_json(force=True)
    c = db()
    c.execute("INSERT INTO announcements(title, body, created_at) VALUES (?,?,?)", (d["title"], d["body"], datetime.utcnow().isoformat()))
    c.commit()
    return jsonify(ok=True), 201

@app.post("/api/admin/programs")
@admin
def add_program():
    d = request.get_json(force=True)
    c = db()
    c.execute(
        "INSERT INTO programs(title, date, time, venue, description, created_at) VALUES (?,?,?,?,?,?)",
        (d["title"], d.get("date", ""), d.get("time", ""), d.get("venue", ""), d.get("description", ""), datetime.utcnow().isoformat())
    )
    c.commit()
    return jsonify(ok=True), 201

@app.get("/health")
def health():
    return jsonify(status="ok", service="HPF Family")

def create_admin():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--phone", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--email", default="")
    ap.add_argument("--campus", default="HPF Family")
    args = ap.parse_args()
    if len(args.password) < 12:
        raise SystemExit("Admin password must be at least 12 characters.")
    c = db()
    existing = c.execute("SELECT id FROM members WHERE phone=?", (args.phone,)).fetchone()
    if existing:
        c.execute(
            "UPDATE members SET role='admin', password_hash=?, name=?, email=?, campus=? WHERE id=?",
            (hp(args.password), args.name, args.email or None, args.campus, existing["id"])
        )
    else:
        c.execute("""INSERT INTO members(name, phone, email, campus, connection, password_hash, role, created_at)
                     VALUES (?,?,?,?,?,?,?,?)""",
                  (args.name, args.phone, args.email or None, args.campus, "HPF Leadership",
                   hp(args.password), "admin", datetime.utcnow().isoformat()))
    c.commit()
    print("HPF admin created/updated successfully.")

@app.route("/")
def home():
    return send_from_directory(BASE, "index.html")

@app.route("/<path:path>")
def static_file(path):
    return send_from_directory(BASE, path)

# Initialize database when the app starts
with app.app_context():
    init_db()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "create-admin":
        create_admin()
    else:
        app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=os.environ.get("FLASK_ENV") != "production")
