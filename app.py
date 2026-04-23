from flask import Flask, render_template, request
import random
import time
import sqlite3

app = Flask(__name__)

# ---------------- DATABASE SETUP ---------------- #
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS otp_requests (
            phone TEXT,
            otp TEXT,
            expiry REAL,
            attempts INTEGER,
            last_sent REAL
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS rate_limits (
            key TEXT,
            timestamp REAL
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS blocks (
            key TEXT,
            blocked_until REAL
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            phone TEXT,
            action TEXT,
            status TEXT,
            time REAL
        )
    ''')

    conn.commit()
    conn.close()

init_db()

# ---------------- LOGGING ---------------- #
def log_event(ip, phone, action, status):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute("INSERT INTO logs (ip, phone, action, status, time) VALUES (?, ?, ?, ?, ?)",
              (ip, phone, action, status, time.time()))

    conn.commit()
    conn.close()

# ---------------- RATE LIMIT ---------------- #
def is_rate_limited(key, limit, window):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    current_time = time.time()

    c.execute("DELETE FROM rate_limits WHERE timestamp < ?", (current_time - window,))
    c.execute("SELECT COUNT(*) FROM rate_limits WHERE key=?", (key,))
    count = c.fetchone()[0]

    if count >= limit:
        conn.close()
        return True

    c.execute("INSERT INTO rate_limits VALUES (?, ?)", (key, current_time))
    conn.commit()
    conn.close()

    return False

# ---------------- BLOCK SYSTEM ---------------- #
def is_blocked(key):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    current_time = time.time()

    c.execute("SELECT blocked_until FROM blocks WHERE key=?", (key,))
    data = c.fetchone()

    if data:
        if current_time < data[0]:
            conn.close()
            return True
        else:
            c.execute("DELETE FROM blocks WHERE key=?", (key,))
            conn.commit()

    conn.close()
    return False

def add_block(key, duration=900):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    blocked_until = time.time() + duration

    # Avoid duplicate block entries
    c.execute("DELETE FROM blocks WHERE key=?", (key,))
    c.execute("INSERT INTO blocks VALUES (?, ?)", (key, blocked_until))

    conn.commit()
    conn.close()

# ---------------- ROUTES ---------------- #
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/send-otp', methods=['POST'])
def send_otp():
    phone = request.form.get('phone')
    ip = request.remote_addr

    # 🚫 Block check
    if is_blocked(f"phone:{phone}") or is_blocked(f"ip:{ip}"):
        log_event(ip, phone, "SEND_OTP", "BLOCKED")
        return render_template('result.html', success=False,
                               message="You are temporarily blocked. Try later.")

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # ⏳ Cooldown
    c.execute("SELECT last_sent FROM otp_requests WHERE phone=?", (phone,))
    data = c.fetchone()

    if data:
        last_sent = data[0]
        if time.time() - last_sent < 30:
            conn.close()
            log_event(ip, phone, "SEND_OTP", "COOLDOWN")
            return render_template('result.html', success=False,
                                   message="Please wait before requesting another OTP.")

    conn.close()

    # 🚫 Rate limiting
    if is_rate_limited(f"phone:{phone}", 3, 60):
        add_block(f"phone:{phone}")
        log_event(ip, phone, "SEND_OTP", "BLOCKED")
        return render_template('result.html', success=False,
                               message="Too many requests. You are temporarily blocked.")

    if is_rate_limited(f"ip:{ip}", 10, 3600):
        add_block(f"ip:{ip}")
        log_event(ip, phone, "SEND_OTP", "BLOCKED")
        return render_template('result.html', success=False,
                               message="Too many requests from your network.")

    # ✅ Generate OTP
    otp = str(random.randint(100000, 999999))
    expiry = time.time() + 300

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute("DELETE FROM otp_requests WHERE phone=?", (phone,))
    c.execute("INSERT INTO otp_requests VALUES (?, ?, ?, ?, ?)",
              (phone, otp, expiry, 0, time.time()))

    conn.commit()
    conn.close()

    print(f"OTP for {phone}: {otp}")

    log_event(ip, phone, "SEND_OTP", "SUCCESS")

    return render_template('verify.html', phone=phone)

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    phone = request.form.get('phone')
    user_otp = request.form.get('otp')
    ip = request.remote_addr

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute("SELECT otp, expiry, attempts FROM otp_requests WHERE phone=?", (phone,))
    data = c.fetchone()

    if not data:
        conn.close()
        log_event(ip, phone, "VERIFY_OTP", "FAILED")
        return render_template('result.html', success=False, message="No OTP found.")

    otp, expiry, attempts = data

    if time.time() > expiry:
        conn.close()
        log_event(ip, phone, "VERIFY_OTP", "EXPIRED")
        return render_template('result.html', success=False, message="OTP expired.")

    if attempts >= 5:
        conn.close()
        log_event(ip, phone, "VERIFY_OTP", "BLOCKED")
        return render_template('result.html', success=False, message="Too many attempts.")

    if user_otp == otp:
        c.execute("DELETE FROM otp_requests WHERE phone=?", (phone,))
        conn.commit()
        conn.close()

        log_event(ip, phone, "VERIFY_OTP", "SUCCESS")
        return render_template('result.html', success=True, message="Verification successful!")
    else:
        c.execute("UPDATE otp_requests SET attempts = attempts + 1 WHERE phone=?", (phone,))
        conn.commit()
        conn.close()

        log_event(ip, phone, "VERIFY_OTP", "FAILED")
        return render_template('result.html', success=False, message="Incorrect OTP.")

# ---------------- DASHBOARD ---------------- #
@app.route('/dashboard')
def dashboard():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Logs
    c.execute("SELECT ip, phone, action, status, time FROM logs ORDER BY time DESC LIMIT 50")
    logs = c.fetchall()

    # Count stats
    c.execute("SELECT COUNT(*) FROM logs WHERE status='SUCCESS'")
    success_count = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM logs WHERE status!='SUCCESS'")
    fail_count = c.fetchone()[0]

    conn.close()

    return render_template('dashboard.html',
                           logs=logs,
                           success_count=success_count,
                           fail_count=fail_count)

# ---------------- RUN ---------------- #
if __name__ == '__main__':
    app.run(debug=True)