from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3, hashlib, secrets, datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = "supersecretkey"
DB = "database.db"

def db(): return sqlite3.connect(DB)

def init_db():
    conn = db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        email TEXT,
        password TEXT,
        admin INTEGER,
        locked INTEGER,
        expires TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS keys (
        key TEXT PRIMARY KEY,
        created_by TEXT,
        used INTEGER,
        used_by TEXT,
        expires TEXT,
        duration TEXT
    )''')
    conn.commit()
    conn.close()

init_db()

def hash_password(p): return hashlib.sha256(p.encode()).hexdigest()
def now(): return datetime.datetime.utcnow()

def add_time(current, duration):
    if current == "lifetime": return "lifetime"
    base = now() if not current else datetime.datetime.fromisoformat(current)
    if duration=="day": return (base+datetime.timedelta(days=1)).isoformat()
    if duration=="week": return (base+datetime.timedelta(weeks=1)).isoformat()
    if duration=="month": return (base+datetime.timedelta(days=30)).isoformat()
    if duration=="year": return (base+datetime.timedelta(days=365)).isoformat()
    return "lifetime"

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        conn = db(); c = conn.cursor()
        u = session.get("username")
        c.execute("SELECT * FROM users WHERE username=?", (u,))
        user = c.fetchone(); conn.close()
        if not u or not user: session.clear(); return redirect("/")
        if user[4]: session.clear(); return "Account Locked"
        if user[5] != "lifetime" and user[5]:
            if now() > datetime.datetime.fromisoformat(user[5]):
                session.clear(); return "Account Expired"
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        conn = db(); c = conn.cursor()
        u = session.get("username")
        c.execute("SELECT admin FROM users WHERE username=?", (u,))
        row = c.fetchone(); conn.close()
        if not row or row[0]!=1: return "Access Denied"
        return f(*args, **kwargs)
    return wrapper

@app.route("/")
def home():
    conn = db(); c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    count = c.fetchone()[0]; conn.close()
    if count==0: session.clear(); return render_template("index.html")
    if session.get("username"): return redirect("/dashboard")
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("username")
    p = hash_password(request.form.get("password"))
    conn = db(); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (u,p))
    user = c.fetchone(); conn.close()
    if user:
        session["username"] = u
        return jsonify({"status":"success"})
    return jsonify({"status":"error"})

@app.route("/register_user", methods=["POST"])
def register():
    u = request.form.get("username")
    email = request.form.get("email")
    p = hash_password(request.form.get("password"))
    key_input = request.form.get("reg_key")
    conn = db(); c = conn.cursor()
    c.execute("SELECT * FROM keys WHERE key=?", (key_input,))
    key = c.fetchone()
    if not key or key[2]==1: return jsonify({"status":"error","message":"Invalid key"})
    expires = key[4]
    # First user becomes admin automatically
    c.execute("INSERT INTO users VALUES (?,?,?,?,?,?)",
              (u,email,p,1 if c.execute("SELECT COUNT(*) FROM users").fetchone()[0]==0 else 0,0,expires))
    c.execute("UPDATE keys SET used=1, used_by=? WHERE key=?", (u,key_input))
    conn.commit(); conn.close()
    return jsonify({"status":"success"})

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session["username"])

@app.route("/admin")
@admin_required
def admin():
    conn = db(); c = conn.cursor()
    users = c.execute("SELECT * FROM users").fetchall()
    keys = c.execute("SELECT * FROM keys").fetchall()
    conn.close()
    return render_template("admin.html", users=users, keys=keys)

@app.route("/generate_key", methods=["POST"])
@admin_required
def generate_key():
    duration = request.form.get("duration")
    new_key = "CSINT-" + secrets.token_hex(4)
    expiry = add_time(None,duration)
    conn = db(); c = conn.cursor()
    c.execute("INSERT INTO keys VALUES (?,?,?,?,?,?)", (new_key, session["username"],0,None,expiry,duration))
    conn.commit(); conn.close()
    return redirect("/admin")

@app.route("/toggle_lock/<user>")
@admin_required
def toggle_lock(user):
    conn = db(); c = conn.cursor()
    c.execute("UPDATE users SET locked = NOT locked WHERE username=?", (user,))
    conn.commit(); conn.close()
    return redirect("/admin")

@app.route("/delete_user/<user>")
@admin_required
def delete_user(user):
    conn = db(); c = conn.cursor()
    c.execute("DELETE FROM users WHERE username=?", (user,))
    conn.commit(); conn.close()
    return redirect("/admin")

@app.route("/reset_pw/<user>")
@admin_required
def reset_pw(user):
    new_pw = secrets.token_hex(4)
    conn = db(); c = conn.cursor()
    c.execute("UPDATE users SET password=? WHERE username=?", (hash_password(new_pw), user))
    conn.commit(); conn.close()
    return f"New password: {new_pw}"

@app.route("/extend/<user>/<duration>")
@admin_required
def extend(user,duration):
    conn = db(); c = conn.cursor()
    c.execute("SELECT expires FROM users WHERE username=?", (user,))
    current = c.fetchone()[0]
    new_exp = add_time(current,duration)
    c.execute("UPDATE users SET expires=? WHERE username=?", (new_exp,user))
    conn.commit(); conn.close()
    return redirect("/admin")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
