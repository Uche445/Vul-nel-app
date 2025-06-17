from flask import Flask, render_template, request, redirect, url_for, flash
import os

# 👇 Explicitly set the template folder path
app = Flask(__name__, template_folder=os.path.join("app", "templates"))
app.secret_key = 'top_secret'

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/scan', methods=['POST'])
def scan():
    scan_type = request.form.get('scan_type')
    target = request.form.get('target') or request.form.get('host') or request.form.get('network')
    flash(f"{scan_type} scan started for target: {target}")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
