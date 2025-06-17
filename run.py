from flask import Flask, render_template, request, redirect, url_for, flash
import os

# Tell Flask to look in app/templates
app = Flask(__name__, template_folder=os.path.join("app", "templates"))
app.secret_key = "top_secret"

@app.route("/", methods=["GET"])
def index():
    return render_template("dashboard.html")

@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target")
    start_port = request.form.get("start_port")
    end_port = request.form.get("end_port")
    flash(f"Scanning {target} from port {start_port} to {end_port}")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
