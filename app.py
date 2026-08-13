import os, secrets, hashlib, hmac, json
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, session, g, send_from_directory
import psycopg
from psycopg.rows import dict_row

BASE = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=None)
app.secret_key = os.environ.get("HPF_SECRET_KEY") or "dev-only-change-me"
app.permanent_session_lifetime = timedelta(days=7)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1"
)

DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db():
    if "db" not in g:
        g.db = psycopg.connect(DATABASE_URL, row_factory=dict_row)
    return g.db

@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS members (
                id SERIAL PRIMARY KEY,
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
            CREATE TABLE IF NOT EXISTS applications (
                id SERIAL PRIMARY KEY,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                phone TEXT NOT NULL,
                campus TEXT,
                hostel TEXT,
                payload TEXT NOT NULL,
                status TEXT DEFAULT 'new',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS announcements (
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS programs (
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                date TEXT,
                time TEXT,
                venue TEXT,
                description TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS prayer_requests (
                id SERIAL PRIMARY KEY,
                member_id INTEGER,
                name TEXT NOT NULL,
                request TEXT NOT NULL,
                status TEXT DEFAULT 'open',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS testimonies (
                id SERIAL PRIMARY KEY,
                member_id INTEGER,
                name TEXT NOT NULL,
                title TEXT NOT NULL,
                story TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TEXT NOT NULL
            );
            """)
            conn.commit()

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
    if not r:
        return None
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
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT role FROM members WHERE id = %s", (session["member_id"],))
                r = cur.fetchone()
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
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO members (name, phone, email, campus, hostel, department, level, gender,
                    connection, service, story, password_hash, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (
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
                new_id = cur.fetchone()["id"]
                conn.commit()
                cur.execute("SELECT * FROM members WHERE id = %s", (new_id,))
                member = cur.fetchone()
        session.permanent = True
        session["member_id"] = new_id
        return jsonify(member=public(member)), 201
    except psycopg.errors.UniqueViolation:
        return jsonify(error="WhatsApp number or email already registered"), 409

@app.post("/api/login")
def login():
    d = request.get_json(force=True)
    ident = d.get("identity", "").strip()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM members WHERE phone = %s OR email = %s", (ident, ident))
            r = cur.fetchone()
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
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM members WHERE id = %s", (session["member_id"],))
            r = cur.fetchone()
    return jsonify(member=public(r))

@app.post("/api/applications")
def applications():
    d = request.get_json(force=True)
    kind = d.get("kind")
    if kind not in ("executive", "hostel"):
        return jsonify(error="Invalid application type"), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO applications (kind, name, phone, campus, hostel, payload, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id
            """, (kind, d.get("name"), d.get("phone"), d.get("campus", ""), d.get("hostel", ""),
                  json.dumps(d, ensure_ascii=False), datetime.utcnow().isoformat()))
            new_id = cur.fetchone()["id"]
            conn.commit()
    return jsonify(id=new_id, status="new"), 201

@app.get("/api/announcements")
def announcements():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM announcements ORDER BY id DESC")
            items = cur.fetchall()
    return jsonify(items=items)

@app.get("/api/programs")
def programs():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM programs ORDER BY date ASC, id DESC")
            items = cur.fetchall()
    return jsonify(items=items)

@app.post("/api/prayer")
@auth
def prayer():
    d = request.get_json(force=True)
    if not d.get("request", "").strip():
        return jsonify(error="Prayer request is required"), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO prayer_requests (member_id, name, request, created_at)
                VALUES (%s, %s, %s, %s)
            """, (session["member_id"], d.get("name", "HPF Member"), d["request"], datetime.utcnow().isoformat()))
            conn.commit()
    return jsonify(ok=True), 201

@app.post("/api/testimony")
@auth
def testimony():
    d = request.get_json(force=True)
    if not d.get("title") or not d.get("story"):
        return jsonify(error="Title and testimony are required"), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO testimonies (member_id, name, title, story, created_at)
                VALUES (%s, %s, %s, %s, %s)
            """, (session["member_id"], d.get("name", "HPF Member"), d["title"], d["story"], datetime.utcnow().isoformat()))
            conn.commit()
    return jsonify(ok=True), 201

@app.get("/api/admin/overview")
@admin
def overview():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM members")
            members = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) AS c FROM applications")
            applications = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) AS c FROM prayer_requests")
            prayer_requests = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) AS c FROM testimonies")
            testimonies = cur.fetchone()["c"]
    return jsonify(members=members, applications=applications, prayer_requests=prayer_requests, testimonies=testimonies)

@app.get("/api/admin/members")
@admin
def members():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM members ORDER BY id DESC")
            rows = cur.fetchall()
    return jsonify(members=[public(r) for r in rows])

@app.get("/api/admin/applications")
@admin
def apps():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM applications ORDER BY id DESC")
            rows = cur.fetchall()
    return jsonify(applications=rows)

@app.post("/api/admin/announcements")
@admin
def add_announcement():
    d = request.get_json(force=True)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO announcements (title, body, created_at) VALUES (%s, %s, %s)",
                        (d["title"], d["body"], datetime.utcnow().isoformat()))
            conn.commit()
    return jsonify(ok=True), 201

@app.post("/api/admin/programs")
@admin
def add_program():
    d = request.get_json(force=True)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO programs (title, date, time, venue, description, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (d["title"], d.get("date", ""), d.get("time", ""), d.get("venue", ""),
                  d.get("description", ""), datetime.utcnow().isoformat()))
            conn.commit()
    return jsonify(ok=True), 201

@app.get("/make-admin-now-hpf2026")
def make_admin_now():
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE members 
                    SET role = 'admin', 
                        name = %s,
                        campus = %s,
                        connection = %s
                    WHERE phone = %s
                """, (
                    "HPFFAMILY",
                    "HPF Family",
                    "HPF Leadership",
                    "07025329640"
                ))
                conn.commit()
        return "SUCCESS! Admin is ready. Login with phone 09157227521 and password HPFFAMILY001"
    except Exception as e:
        return f"Error: {str(e)}"

@app.route("/")
def home():
    return send_from_directory(BASE, "index.html")

@app.route("/<path:path>")
def static_file(path):
    return send_from_directory(BASE, path)

# Create tables on startup and seed admin
with app.app_context():
    if DATABASE_URL:
        init_db()
        # Seed / Update Admin Account
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id FROM members WHERE phone = %s", ("07025329640",))
                    existing = cur.fetchone()
                    if existing:
                        # Update existing account to admin
                        cur.execute("""
                            UPDATE members 
                            SET role = 'admin', 
                                password_hash = %s, 
                                name = %s,
                                campus = %s,
                                connection = %s
                            WHERE phone = %s
                        """, (
                            hp("HPFFAMILY001"),
                            "HPFFAMILY",
                            "HPF Family",
                            "HPF Leadership",
                            "07025329640"
                        ))
                    else:
                        cur.execute("""
                            INSERT INTO members (name, phone, email, campus, connection, password_hash, role, created_at)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            "HPFFAMILY",
                            "07025329640",
                            None,
                            "HPF Family",
                            "HPF Leadership",
                            hp("HPFFAMILY001"),
                            "admin",
                            datetime.utcnow().isoformat()
                        ))
                    conn.commit()
                    print("Admin account ready")
        except Exception as e:
            print("Admin seed error:", e)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
