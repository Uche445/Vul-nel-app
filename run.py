from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from datetime import datetime
import os
import csv
from flask import make_response
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

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

    # ✅ Load scan logs
    log_file = os.path.join('logs', 'scan.log')
    scan_logs = []
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            scan_logs = f.readlines()

    return render_template('dashboard.html', scan_results=scan_results, scan_logs=scan_logs)

@app.route('/scan', methods=['POST'])
def scan():
    scan_type = request.form.get('scan_type')

    # 🔍 Port Scan
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

    # 🔐 Brute Force
    elif scan_type == "Brute Force":
        target = request.form.get("host")
        service = request.form.get("service")
        wordlist_file = request.files.get("wordlist")

        if wordlist_file:
            wordlist_path = os.path.join("uploads", wordlist_file.filename)
            wordlist_file.save(wordlist_path)

            result = brute_force(target, service, wordlist_path)

            status = "Completed" if "success" in result else "Failed"
            findings = result.get("success") or result.get("error", "No credentials found.")
            flash(f"{service} brute force: {findings}")
            save_scan_result("Brute Force", target, status, findings)
        else:
            flash("No wordlist uploaded.")
            save_scan_result("Brute Force", target, "Error", "Missing wordlist.")

    # 🌐 TCP/IP Scan
    elif scan_type == "TCP/IP Scanner":
        network = request.form.get("network")
        protocol = request.form.get("protocol", "TCP")
        result = scan_network_range(network, protocol)

        if "error" in result:
            flash(result["error"])
            save_scan_result("TCP/IP Scanner", network, "Error", result["error"])
        else:
            findings = f"{len(result['hosts'])} hosts responded"
            flash(findings)
            save_scan_result("TCP/IP Scanner", network, "Completed", findings)

    # 🖥️ SSH Scan
    elif scan_type == "SSH Scanner":
        target = request.form.get("host")
        port = request.form.get("port", 22)

        try:
            result = ssh_check_host(target, int(port))
            findings = result.get("message", "SSH scan completed.")
            status = "Completed" if result.get("success") else "Failed"
        except Exception as e:
            findings = str(e)
            status = "Error"

        flash(f"SSH: {findings}")
        save_scan_result("SSH Scanner", target, status, findings)

    else:
        flash(f"{scan_type} scan initiated (not implemented).")
        target = request.form.get('target') or request.form.get('host') or request.form.get('network')
        save_scan_result(scan_type, target, "Pending", "Scan queued or not implemented.")

    return redirect(url_for('index'))

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


# ✅ PDF Export Route
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
