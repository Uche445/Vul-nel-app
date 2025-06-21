from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
from datetime import datetime
import os
import csv
from flask import make_response
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import socket
import threading
import time

from app.models import db, ScanResult
from scanner.port_scanner import scan_ports
from scanner.brute_force import brute_force
from scanner.tcp_ip_scanner import scan_network_range
from scanner.ssh_scanner import ssh_check_host

# ✅ Flask app setup
app = Flask(
    __name__,
    template_folder=os.path.join("app", "templates"),
    static_folder=os.path.join("app", "static"),
    static_url_path='/static'
)
app.secret_key = 'top_secret'

# ✅ SQLAlchemy config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scan_results.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# ✅ Create DB tables
with app.app_context():
    db.create_all()

# ✅ Reusable scan saving logic
def save_scan_result(scan_type, target, status, findings):
    result = ScanResult(
        scan_type=scan_type,
        target=target,
        status=status,
        findings=findings,
        timestamp=datetime.now().strftime("%Y-%m-%d %I:%M %p")
    )
    db.session.add(result)
    db.session.commit()

@app.route('/')
def index():
    scan_results = ScanResult.query.order_by(ScanResult.id.desc()).all()

    log_file = os.path.join('logs', 'scan.log')
    scan_logs = []
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            scan_logs = f.readlines()

    return render_template('dashboard.html', scan_results=scan_results, scan_logs=scan_logs)

@app.route('/scan', methods=['POST'])
def scan():
    scan_type = request.form.get('scan_type')

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
            save_scan_result("Port Scan", target, "Error", result["error"])
        else:
            ports = result['open_ports']
            findings = f"{len(ports)} open ports: {', '.join(map(str, ports))}"
            flash(f"Open ports on {target}: {findings}")
            save_scan_result("Port Scan", target, "Completed", findings)

    elif scan_type == "Brute Force":
        target = request.form.get("host")
        service = request.form.get("service")
        wordlist_file = request.files.get("wordlist")

        if wordlist_file:
            upload_dir = os.path.join("uploads")
            os.makedirs(upload_dir, exist_ok=True)
            wordlist_path = os.path.join(upload_dir, wordlist_file.filename)
            wordlist_file.save(wordlist_path)

            result = brute_force(target, service, wordlist_path)

            status = "Completed" if "success" in result else "Failed"
            findings = result.get("success") or result.get("error", "No credentials found.")
            flash(f"{service} brute force: {findings}")
            save_scan_result("Brute Force", target, status, findings)
        else:
            flash("No wordlist uploaded.")
            save_scan_result("Brute Force", target, "Error", "Missing wordlist.")

    elif scan_type == "TCP/IP Scanner":
        network = request.form.get("network")
        protocol = request.form.get("protocol", "TCP")
        result = scan_network_range(network)

        if "error" in result:
            flash(result["error"])
            save_scan_result("TCP/IP Scanner", network, "Error", result["error"])
        else:
            findings = f"{len(result['active_hosts'])} hosts responded"
            flash(findings)
            save_scan_result("TCP/IP Scanner", network, "Completed", findings)

    elif scan_type == "SSH Scanner":
    # 🛡️ Define all needed variables BEFORE try block
     target = request.form.get("host") or "N/A"
    port = int(request.form.get("port", 22))
    username = request.form.get("username")
    password = request.form.get("password")

    try:
        result = ssh_check_host(target, port, username=username, password=password)
        status = result.get("status", "Completed")

        findings = ""
        for item in result.get("findings", []):
            if isinstance(item, dict):
                findings += f"{item['title']} (CVE: {', '.join(item['cve']) or 'N/A'}) - Fix: {item['remediation']}\n"
            else:
                findings += f"{item}\n"

        flash(f"SSH Scan complete for {target}")
        save_scan_result("SSH Scanner", target, status, findings.strip())

    except Exception as e:
        flash(f"SSH Scan failed: {str(e)}")
        save_scan_result("SSH Scanner", target, "Error", str(e))


    else:
        flash(f"{scan_type} scan initiated (not implemented).")
        target = request.form.get('target') or request.form.get('host') or request.form.get('network')
        save_scan_result(scan_type, target, "Pending", "Scan queued or not implemented.")

    return redirect(url_for('index'))

@app.route('/auto-scan', methods=['POST'])
def auto_scan():
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_path = os.path.join("logs", "scan.log")
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        with open(log_path, 'a', encoding='utf-8') as log:
            log.write(f"[INFO] Auto scan triggered at {timestamp}\n")

        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"

        progress_path = os.path.join("logs", "progress.txt")
        with open(progress_path, "w") as f:
            f.write("0")

        # TCP/IP Scan
        tcp_result = scan_network_range(subnet)
        with open(progress_path, "w") as f:
            f.write("33")

        if "error" not in tcp_result:
            save_scan_result("TCP/IP Scanner", subnet, "Completed",
                             f"{len(tcp_result['active_hosts'])} hosts responded")

        # SSH Scan
        for host in tcp_result.get("active_hosts", []):
            try:
                result = ssh_check_host(host, 22)
                status = "Completed" if result.get("success") else "Failed"
                save_scan_result("SSH Scanner", host, status, result.get("message", ""))
            except Exception as e:
                save_scan_result("SSH Scanner", host, "Error", str(e))

        with open(progress_path, "w") as f:
            f.write("66")

        # Port Scan
        port_result = scan_ports(local_ip, 20, 1024)
        if "error" not in port_result:
            ports = port_result['open_ports']
            findings = f"{len(ports)} open ports: {', '.join(map(str, ports))}"
            save_scan_result("Port Scan", local_ip, "Completed", findings)

        # ✅ Auto Scan summary (YAML-style plaintext)
        port_summary = f"Port Scan: {len(ports)} open ports ({', '.join(map(str, ports))})"
        tcp_summary = f"TCP/IP Scanner: {len(tcp_result['active_hosts'])} hosts alive"
        ssh_summary = "SSH Scanner: SSH service accessible"

        auto_findings = f"{port_summary}\n{tcp_summary}\n{ssh_summary}"
        save_scan_result("Auto Scan", local_ip, "Completed", auto_findings)

        with open(progress_path, "w") as f:
            f.write("100")

        return jsonify({"success": True})

    except Exception as e:
        with open("logs/scan.log", "a", encoding='utf-8') as log:
            log.write(f"[ERROR] Auto scan failed: {str(e)}\n")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/auto-scan/progress')
def auto_scan_progress():
    progress_path = os.path.join("logs", "progress.txt")
    if os.path.exists(progress_path):
        with open(progress_path, "r") as f:
            percent = f.read().strip()
        return jsonify({"progress": percent})
    return jsonify({"progress": "0"})

@app.route('/result/<int:result_id>')
def view_result(result_id):
    result = ScanResult.query.get_or_404(result_id)
    return render_template('result_detail.html', result=result)

@app.route('/export/csv')
def export_csv():
    results = ScanResult.query.order_by(ScanResult.id.desc()).all()

    output = []
    output.append(['Scan Type', 'Target', 'Status', 'Findings', 'Timestamp'])

    for r in results:
        output.append([r.scan_type, r.target, r.status, r.findings, r.timestamp])

    response = make_response()
    writer = csv.writer(response)
    writer.writerows(output)

    response.headers['Content-Disposition'] = 'attachment; filename=scan_results.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response

@app.route('/export/pdf/<int:result_id>')
def export_pdf(result_id):
    result = ScanResult.query.get_or_404(result_id)

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica", 12)

    y = 750
    p.drawString(100, y, f"Scan Type: {result.scan_type}")
    y -= 20
    p.drawString(100, y, f"Target: {result.target}")
    y -= 20
    p.drawString(100, y, f"Status: {result.status}")
    y -= 20
    p.drawString(100, y, f"Time: {result.timestamp}")
    y -= 30
    p.drawString(100, y, "Findings:")

    for line in result.findings.split(','):
        y -= 20
        p.drawString(120, y, f"- {line.strip()}")

    p.showPage()
    p.save()
    buffer.seek(0)

    return send_file(buffer, as_attachment=True,
                     download_name=f"scan_result_{result_id}.pdf",
                     mimetype='application/pdf')

if __name__ == '__main__':
    app.run(debug=True)
