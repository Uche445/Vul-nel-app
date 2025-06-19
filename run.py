from flask import Flask, render_template, request, redirect, url_for, flash
from datetime import datetime
import os
import logging

from app.models import db, ScanResult
from scanner.port_scanner import scan_ports
from scanner.brute_force import brute_force

# ✅ Flask app setup with templates & static
app = Flask(
    __name__,
    template_folder=os.path.join("app", "templates"),
    static_folder=os.path.join("app", "static"),
    static_url_path='/static'
)
app.secret_key = 'top_secret'

# 🔌 SQLAlchemy config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scan_results.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# 📝 Logging setup
logging.basicConfig(
    filename='scan_activity.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 🔧 Create DB tables
with app.app_context():
    db.create_all()

# 🏠 Home route (dashboard)
@app.route('/')
def index():
    scan_results = ScanResult.query.order_by(ScanResult.id.desc()).all()
    return render_template('dashboard.html', scan_results=scan_results)

# 🚀 Scan logic route
@app.route('/scan', methods=['POST'])
def scan():
    scan_type = request.form.get('scan_type')
    client_ip = request.remote_addr  # 🌐 Track user IP

    # ⚡ Port Scanner Logic
    if scan_type == "Port Scan":
        target = request.form.get("target")
        try:
            start_port = int(request.form.get("start_port", 1))
            end_port = int(request.form.get("end_port", 1024))
        except ValueError:
            flash("Invalid port range.")
            return redirect(url_for("index"))

        result = scan_ports(target, start_port, end_port)

        if "error" in result:
            flash(result["error"])
            logging.error(f"Port scan error for {target} ({client_ip}): {result['error']}")
        else:
            findings = f"{len(result['open_ports'])} open ports"
            flash(f"Open ports on {target}: {findings}")
            logging.info(f"Port scan completed for {target} ({client_ip}): {findings}")

            new_result = ScanResult(
                scan_type="Port Scan",
                target=target,
                status="Completed",
                findings=findings + f" | Requested from {client_ip}",
                timestamp=datetime.now().strftime("%Y-%m-%d %I:%M %p")
            )
            db.session.add(new_result)
            db.session.commit()

    # 🛡️ Brute Force Logic
    elif scan_type == "Brute Force":
        service = request.form.get("service")
        host = request.form.get("host")
        wordlist_file = request.files.get("wordlist")

        if not wordlist_file:
            flash("No wordlist file uploaded.")
            return redirect(url_for("index"))

        wordlist = [line.strip() for line in wordlist_file.read().decode().splitlines() if line.strip()]
        preview = ", ".join(wordlist[:5]) + ("..." if len(wordlist) > 5 else "")

        result = brute_force(service, host, wordlist)
        findings = f"{result['message']} | Preview: {preview} | IP: {client_ip}"
        flash(findings)
        logging.info(f"Brute force attempt on {service}@{host} ({client_ip}): {result['message']}")

        new_result = ScanResult(
            scan_type="Brute Force",
            target=f"{service}@{host}",
            status="Completed" if result["success"] else "Failed",
            findings=findings,
            timestamp=datetime.now().strftime("%Y-%m-%d %I:%M %p")
        )
        db.session.add(new_result)
        db.session.commit()

    else:
        flash(f"{scan_type} scan initiated (not implemented).")
        logging.warning(f"Unimplemented scan type triggered by {client_ip}: {scan_type}")

    return redirect(url_for('index'))

@app.route('/logs')
def logs():
    try:
        with open("scan_activity.log") as f:
            lines = f.readlines()[-30:]  # adjust the number if needed
        return {"logs": lines}
    except Exception as e:
        return {"logs": [f"Error reading log: {str(e)}"]}


if __name__ == '__main__':
    app.run(debug=True)
