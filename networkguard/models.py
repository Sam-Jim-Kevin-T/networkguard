from datetime import datetime, timezone

from werkzeug.security import generate_password_hash

from .extensions import db


def utcnow():
    return datetime.now(timezone.utc)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    servers = db.relationship("Server", back_populates="owner", cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)


class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    hostname = db.Column(db.String(255), nullable=True)
    agent_token_hash = db.Column(db.String(64), nullable=False, unique=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    owner = db.relationship("User", back_populates="servers")
    snapshots = db.relationship("MetricSnapshot", back_populates="server", cascade="all, delete-orphan")
    alerts = db.relationship("Alert", back_populates="server", cascade="all, delete-orphan")


class MetricSnapshot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey("server.id", ondelete="CASCADE"), nullable=False, index=True)
    recorded_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    cpu_percent = db.Column(db.Float, nullable=False)
    memory_percent = db.Column(db.Float, nullable=False)
    tcp_connections = db.Column(db.Integer, nullable=False, default=0)
    udp_connections = db.Column(db.Integer, nullable=False, default=0)
    network_in_bytes = db.Column(db.BigInteger, nullable=False, default=0)
    network_out_bytes = db.Column(db.BigInteger, nullable=False, default=0)
    failed_ssh_attempts = db.Column(db.Integer, nullable=False, default=0)
    listening_ports = db.Column(db.JSON, nullable=False, default=list)
    connections = db.Column(db.JSON, nullable=False, default=list)
    server = db.relationship("Server", back_populates="snapshots")


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey("server.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_key = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(160), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="active", index=True)
    first_seen_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    server = db.relationship("Server", back_populates="alerts")


def password_is_valid(password):
    return isinstance(password, str) and 12 <= len(password) <= 128
