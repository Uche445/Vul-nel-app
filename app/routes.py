from flask import app, render_template, request, redirect, url_for, flash

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target')
    # Do NOT run long scans here directly!
    flash(f"Scan started for {target}")
    return redirect(url_for('dashboard'))