# Author: TK
# Date: 03-03-2026
# Purpose: initialise app make it a package

import os
from flask import flask
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

db = SQLAlchemy()

def create_app():
    load_dotenv()
    app = Flask(__name__, instance_relative_config=True)
    app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET", "dev")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///instance/scans.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["REDIS_URL"] = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    app.config["ALLOWED_CIDR"] = os.getenv("ALLOWED_CIDR", "192.168.56.0/24")

    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)

    from .routes import bp
    app.register_blueprint(bp)

    with app.app_context():
        from .models import Scan, Finding
        db.create_all()

    return app
