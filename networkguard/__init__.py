import os
from datetime import timedelta

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from flask_limiter.errors import RateLimitExceeded
from flask_wtf.csrf import CSRFError, CSRFProtect, generate_csrf
from sqlalchemy import text
from werkzeug.middleware.proxy_fix import ProxyFix

from .extensions import db, limiter

csrf = CSRFProtect()


def database_uri_from_env(value):
    if value.startswith("postgres://"):
        return "postgresql+psycopg://" + value.removeprefix("postgres://")
    if value.startswith("postgresql://"):
        return "postgresql+psycopg://" + value.removeprefix("postgresql://")
    return value


def create_app(test_config=None):
    load_dotenv()
    app = Flask(__name__)
    configured_database_url = os.getenv("DATABASE_URL")
    if os.getenv("RENDER") and not configured_database_url:
        raise RuntimeError("Set DATABASE_URL to a persistent PostgreSQL database on Render.")
    if os.getenv("RENDER") and not configured_database_url.startswith(("postgres://", "postgresql://", "postgresql+psycopg://")):
        raise RuntimeError("Render deployments require a persistent PostgreSQL DATABASE_URL.")
    app.config.from_mapping(
        SECRET_KEY=os.getenv("SECRET_KEY"),
        SQLALCHEMY_DATABASE_URI=database_uri_from_env(
            configured_database_url or "sqlite:///networkguard.db"
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower() == "true",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
        MAX_CONTENT_LENGTH=1_048_576,
    )
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        raise RuntimeError("Set SECRET_KEY in the environment before starting the app.")

    if os.getenv("RENDER"):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    db.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)

    from .routes import api

    app.register_blueprint(api, url_prefix="/api")

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/csrf")
    def csrf_token():
        return jsonify(csrf_token=generate_csrf())

    @app.get("/healthz")
    def health_check():
        db.session.execute(text("SELECT 1"))
        return jsonify(status="ok")

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        return jsonify(error="csrf_failed", message=error.description), 400

    @app.errorhandler(413)
    def handle_request_too_large(_error):
        return jsonify(error="request_too_large"), 413

    @app.errorhandler(RateLimitExceeded)
    def handle_rate_limit(error):
        return jsonify(error="rate_limit_exceeded", message=error.description), 429

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        if request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000"
            )
        return response

    with app.app_context():
        db.create_all()

    return app
