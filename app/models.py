from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(100), nullable=False)
    target = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    findings = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.String(100), nullable=False)
