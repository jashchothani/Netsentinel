from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import sqlite3
import random
from packet_monitor import start_sniffing_thread, get_traffic_data
from ai_detector import evaluate_devices
from packet_monitor import ai_device_stats
from scanner import known_devices # To get device names
from system_logger import log_event
from speed_tester import run_speed_test
# Import your real network scanner!
from scanner import scan_network
from firewall import block_ip_in_firewall, unblock_ip_in_firewall, get_active_rules
from email_verifier import verify_payment_auto
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.environ.get('NETSENTINEL_SECRET_KEY', 'change-this-secret-key')

# --- Email Configuration ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  # Changed from 465
app.config['MAIL_USE_TLS'] = True  # Changed to TLS
app.config['MAIL_USE_SSL'] = False # Turned off SSL
app.config['MAIL_USERNAME'] = os.environ.get('NETSENTINEL_MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('NETSENTINEL_MAIL_PASSWORD', '')

app.config['MAIL_DEFAULT_SENDER'] = 'jashthakkar77@gmail.com'

mail = Mail(app)

# --- Database Helper ---
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# --- Route Helpers ---
def generate_otp():
    return str(random.randint(100000, 999999))

@app.route("/")
def landing():
    return render_template("landing.html")
@app.route("/upgrade")
def upgrade():
    return render_template("upgrade.html")
@app.route("/mannual")
def mannual():
    return render_template("howitworks.html")
# --- Register Route ---
@app.route("/register", methods=['GET', 'POST'])
def register():
    # Block logged-in users from seeing the register page
    if 'username' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        user_check = conn.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, email)).fetchone()
        conn.close()

        if user_check:
            flash("Username or Email already exists!")
            return redirect(url_for('register'))

        # Temporarily store data in session and send OTP
        otp = generate_otp()
        session['temp_user'] = {
            'username': username,
            'email': email,
            'password_hash': generate_password_hash(password),
            'action': 'register'
        }
        session['otp'] = otp

        # Send OTP Email
        msg = Message("NetSentinel - Your Verification Code", recipients=[email])
        msg.body = f"Your verification code is: {otp}"
        mail.send(msg)

        return redirect(url_for('verify_otp'))

    return render_template("register.html")

# --- Login Route ---
@app.route("/login", methods=['GET', 'POST'])
def login():
    # Block logged-in users from seeing the login page
    if 'username' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password_attempt = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password_attempt):
            
            # --- ADMIN OTP BYPASS ---
            if username.lower() == 'admin':
                # Log the admin in immediately, skip OTP and email
                session['username'] = user['username']
                log_event("Auth", "Info", f"Admin user '{username}' logged in successfully.", request.remote_addr)
                return redirect(url_for('dashboard'))
            # ------------------------

            # Credentials are correct, initiate OTP sequence for normal users
            otp = generate_otp()
            session['temp_user'] = {
                'username': user['username'],
                'email': user['email'],
                'action': 'login'
            }
            session['otp'] = otp

            # Send OTP Email
            msg = Message("NetSentinel - Login Verification", recipients=[user['email']])
            msg.body = f"Your login verification code is: {otp}"
            mail.send(msg)

            return redirect(url_for('verify_otp'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))

    return render_template("login.html")
@app.route("/forgot-password", methods=['GET', 'POST'])
def forgot_password():
    if 'username' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        action = request.form.get('action')

        # --- STEP 1: SEND OTP ---
        if action == 'send_otp':
            email = request.form.get('email').strip()
            
            conn = get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            conn.close()

            if user:
                # Generate a 6-digit OTP
                import random
                otp = str(random.randint(100000, 999999))
                session['reset_email'] = email
                session['reset_otp'] = otp
                
                # Send the Recovery Email
                try:
                    msg = Message("NetSentinel - Password Reset Code", recipients=[email])
                    msg.body = f"Your password reset code is: {otp}\nIf you did not request this, please ignore this email."
                    mail.send(msg)
                except Exception as e:
                    print(f"Failed to send reset email: {e}")
                
            # Always show success to prevent email snooping
            flash("If an account exists with that email, a reset code has been sent.", "success")
            return redirect(url_for('forgot_password'))

        # --- STEP 2: VERIFY & RESET PASSWORD ---
        elif action == 'reset':
            user_otp = request.form.get('otp').strip()
            new_password = request.form.get('new_password')
            reset_email = session.get('reset_email')

            if user_otp == session.get('reset_otp') and reset_email:
                hashed_pw = generate_password_hash(new_password)
                
                conn = get_db_connection()
                conn.execute('UPDATE users SET password_hash = ? WHERE email = ?', (hashed_pw, reset_email))
                conn.commit()
                conn.close()
                
                # Clean up the session
                session.pop('reset_email', None)
                session.pop('reset_otp', None)
                
                flash("Password successfully reset! You can now log in.", "success")
                return redirect(url_for('login'))
            else:
                flash("Invalid or expired reset code. Please try again.", "error")
                return redirect(url_for('forgot_password'))

    # Render the page (Passes True if they are in the OTP phase)
    show_otp_step = 'reset_email' in session
    return render_template("forgot_password.html", show_otp_step=show_otp_step)
# --- FIREWALL ACTIVE DEFENSE API ---
@app.route("/api/block", methods=['POST'])
def api_block_ip():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Get the IP address sent from the JavaScript button
    data = request.get_json()
    ip_to_block = data.get('ip')
    
    if not ip_to_block:
        return jsonify({"success": False, "error": "No IP provided"})
        
    # Trigger the Windows Firewall
    result = block_ip_in_firewall(ip_to_block)
    return jsonify(result)
# --- OTP Verification Route ---
@app.route("/verify_otp", methods=['GET', 'POST'])
def verify_otp():
    if 'temp_user' not in session or 'otp' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_otp_entry = request.form['otp']

        if user_otp_entry == session['otp']:
            temp_user = session['temp_user']
            email_to_notify = temp_user['email']

            if temp_user['action'] == 'register':
                conn = get_db_connection()
                conn.execute(
                    'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', 
                    (temp_user['username'], temp_user['email'], temp_user['password_hash'])
                )
                conn.commit()
                conn.close()

            elif temp_user['action'] == 'login':
                pass

            # Clear session + login
            session.pop('temp_user', None)
            session.pop('otp', None)
            session['username'] = temp_user['username']

            # ✅ MOVE THIS INSIDE
            conn = get_db_connection()
            payment = conn.execute(
                "SELECT * FROM manual_payments WHERE username=? AND status='Approved'",
                (temp_user['username'],)
            ).fetchone()
            conn.close()

            if payment:
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('payment_page'))

        else:
            flash("Invalid OTP. Please try again.")

    return render_template("verify.html")

# --- Dashboard & Logout ---
@app.route("/dashboard")
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    # 🔥 ADMIN BYPASS
    if username.lower() == "admin":
        return render_template("dashboard.html", username=username)

    # 🔒 NORMAL USERS → CHECK PAYMENT
    conn = get_db_connection()
    payment = conn.execute(
        "SELECT * FROM manual_payments WHERE username=? AND status='Approved'",
        (username,)
    ).fetchone()
    conn.close()

    if not payment:
        return redirect(url_for('payment_page'))

    return render_template("dashboard.html", username=username)

@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect(url_for('landing'))
# --- BANDWIDTH SPEED TEST API ---
@app.route("/api/speedtest")
def api_speedtest():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Run the test and return the results
    results = run_speed_test()
    return jsonify(results)
# --- THE LIVE SCANNER API ---
@app.route("/api/scan")
def api_scan():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
        
    print("Running background Nmap scan...")
    # This runs your scanner.py script
    live_devices = scan_network() 
    
    # Sends the data back to the dashboard as JSON
    return jsonify(live_devices)
# --- THE LIVE TRAFFIC API ---
@app.route("/api/traffic")
def api_traffic():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Return the real-time packet counts and the live feed
    return jsonify(get_traffic_data())

@app.route("/traffic")
def traffic_monitor():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("traffic.html", username=session['username'])
@app.route("/alerts")
def alerts_page():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("alerts.html", username=session['username'])
# --- NETWORK TOPOLOGY ROUTE ---
@app.route("/topology")
def topology():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("topology.html", username=session['username'])

# --- PREMIUM FEATURE GATEWAY ---
# --- FIREWALL MANAGEMENT PAGE ---
@app.route("/firewall")
def firewall_page():
    if 'username' not in session: return redirect(url_for('login'))
    return render_template("firewall.html", username=session['username'])
@app.route("/api/firewall/rules")
def api_firewall_rules():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_active_rules())

@app.route("/api/firewall/unblock", methods=['POST'])
def api_unblock_ip():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    ip_to_unblock = request.get_json().get('ip')
    result = unblock_ip_in_firewall(ip_to_unblock)
    return jsonify(result)

@app.route("/api/ai_risk")
def api_ai_risk():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    
    # Merge Scapy live traffic with Nmap device types
    formatted_stats = {}
    for ip, data in ai_device_stats.items():
        # Find device type from Nmap memory if available
        device_type = "Unknown Device"
        for mac, dev in known_devices.items():
            if dev['ip'] == ip:
                device_type = dev['type']
                break
                
        formatted_stats[ip] = {
            "packets": data["packets"],
            "ports": len(data["ports"]),
            "bytes": data["bytes"],
            "type": device_type
        }
        
    # Run the Machine Learning model
    ai_results = evaluate_devices(formatted_stats)
    return jsonify(ai_results)
@app.route("/resources")
def resources():
    return render_template("resources.html")
# --- HISTORICAL SYSTEM LOGS API ---
@app.route("/api/logs")
def api_logs():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    try:
        conn = sqlite3.connect('system_logs.db')
        conn.row_factory = sqlite3.Row
        db_logs = conn.execute('SELECT * FROM logs ORDER BY id DESC LIMIT 150').fetchall()
        conn.close()
        return jsonify([dict(row) for row in db_logs])
    except Exception as e:
        return jsonify([])

@app.route("/api/clear_logs", methods=['POST'])
def clear_logs():
    if 'username' not in session: return jsonify({"error": "Unauthorized"}), 401
    conn = sqlite3.connect('system_logs.db')
    conn.execute('DELETE FROM logs')
    conn.commit()
    conn.close()
    log_event("System", "Warning", "Admin manually cleared the system logs.")
    return jsonify({"success": True})
# --- AI DASHBOARD PAGE ---
@app.route("/ai-threat-engine")
def ai_engine():
    if 'username' not in session: return redirect(url_for('login'))
    return render_template("ai_detector.html", username=session['username'])
import os
import random
import qrcode
from datetime import datetime, timedelta

@app.route("/payment")
def payment_page():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    
    # Admin Bypass
    if username.lower() == "admin":
        return redirect(url_for('dashboard'))
        
    conn = get_db_connection()

    # 1. FIX: Check actual subscription expiry, NOT just past payment status!
    user = conn.execute("SELECT subscription_end FROM users WHERE username=?", (username,)).fetchone()
    if user and user['subscription_end']:
        expiry_date = datetime.strptime(user['subscription_end'], '%Y-%m-%d %H:%M:%S')
        if datetime.now() < expiry_date:
            conn.close()
            return redirect(url_for('dashboard')) # Still active!

    # 2. Check for an existing PENDING payment
    pending = conn.execute(
        "SELECT * FROM manual_payments WHERE username=? AND status='Pending'",
        (username,)
    ).fetchone()

    base_price = 2 # Change this to your actual price!

    if pending and 'payment_amount' in session:
        # Reuse the exact amount they were already assigned
        amount = session['payment_amount']
    else:
        # 3. FIX: The Penny Drop System. Generate a unique decimal so emails don't overlap!
        unique_cents = random.randint(1, 99) / 100.0
        amount = round(base_price + unique_cents, 2)
        session['payment_amount'] = amount

        fake_utr = "AUTO_" + datetime.now().strftime("%Y%m%d%H%M%S")
        conn.execute(
            "INSERT INTO manual_payments (username, plan, payment_code, utr, status) VALUES (?, ?, ?, ?, ?)",
            (username, "Pro Plan", "AUTO", fake_utr, "Pending")
        )
        conn.commit()
        
    conn.close()

    # 4. GENERATE QR CODE
    upi_id = "9004976777@fam"
    upi_url = f"upi://pay?pa={upi_id}&pn=NetSentinel&am={amount}&cu=INR"

    os.makedirs("static/qr", exist_ok=True)
    
    # FIX: Add the amount to the filename so the browser never caches an old QR code
    safe_amount_str = str(amount).replace('.', '_')
    filename = f"{username}_{safe_amount_str}.png"
    qr_path = f"static/qr/{filename}"

    # Only generate the image if this specific one doesn't exist yet
    if not os.path.exists(qr_path):
        img = qrcode.make(upi_url)
        img.save(qr_path)

    # Note: Added the leading slash so HTML finds it correctly from any route
    return render_template("pricing.html", qr_path="/" + qr_path, amount=amount)


@app.route("/api/check-payment", methods=['POST'])
def check_payment():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    username = session['username']
    amount = session.get('payment_amount')
    days = session.get('subscription_days', 30)

    if not amount:
        return jsonify({"verified": False})

    print(f"Checking Inbox for exact amount: ₹{amount}")

    # Make sure verify_payment_auto is imported at the top of your file!
    is_verified = verify_payment_auto(amount)

    if is_verified:
        conn = get_db_connection()

        # Update their pending payment to approved
        conn.execute(
            "UPDATE manual_payments SET status='Approved' WHERE username=? AND status='Pending'",
            (username,)
        )

        # Extend their subscription time
        expiry = datetime.now() + timedelta(days=days)
        conn.execute(
            "UPDATE users SET subscription_end=? WHERE username=?",
            (expiry.strftime('%Y-%m-%d %H:%M:%S'), username)
        )

        conn.commit()
        conn.close()
        
        # Clear the amount from the session so they get a fresh one next time they renew
        session.pop('payment_amount', None)

        return jsonify({"verified": True})

    return jsonify({"verified": False})
@app.route("/test-attack")
def test_attack():
    from sniffer import traffic
    
    # Inject a massive fake Nmap scan from a hostile IP into the sniffer's memory
    attacker_ip = "185.20.9.44"
    
    # Initialize the dictionary structure if it doesn't exist
    if attacker_ip not in traffic:
        traffic[attacker_ip] = {"packets": 0, "bytes": 0, "ports": set(), "type": "Unknown"}
        
    # Simulate the attack payload
    traffic[attacker_ip]["packets"] += 850
    traffic[attacker_ip]["bytes"] += 45000
    traffic[attacker_ip]["ports"].update(range(20, 120)) # Simulates scanning 100 different ports
    
    return "<h3>⚠️ Fake attack injected into memory! Go check your NetSentinel dashboard.</h3>"
if __name__ == "__main__":
    # Boot up the packet sniffer in the background
    start_sniffing_thread()
    app.run(debug=True, use_reloader=False) # use_reloader=False prevents double-sniffing