import hashlib
import hmac
import math
import secrets
from datetime import timedelta
from functools import wraps

from flask import Blueprint, jsonify, request, session
from sqlalchemy import func
from werkzeug.security import check_password_hash

from . import csrf
from .extensions import db, limiter
from .models import Alert, MetricSnapshot, Server, User, password_is_valid, utcnow

api = Blueprint("api", __name__)
ONLINE_WINDOW = timedelta(seconds=90)
SSH_FAILURE_THRESHOLD = 5
TRAFFIC_SPIKE_FLOOR = 10 * 1024 * 1024
TRAFFIC_SPIKE_MULTIPLIER = 4


def error(message, status):
    return jsonify(error=message), status


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return error("authentication_required", 401)
        return view(*args, **kwargs)

    return wrapped


def current_user():
    return db.session.get(User, session["user_id"])


def owned_server(server_id):
    return Server.query.filter_by(id=server_id, owner_id=session["user_id"]).first()


def server_json(server, latest=None, now=None):
    now = now or utcnow()
    last_seen = server.last_seen_at
    if last_seen and last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=now.tzinfo)
    online = last_seen is not None and now - last_seen <= ONLINE_WINDOW
    active_alerts = [alert for alert in server.alerts if alert.status == "active"]
    if any(alert.severity in ("critical", "high") for alert in active_alerts):
        risk = "HIGH"
    elif active_alerts:
        risk = "MEDIUM"
    else:
        risk = "LOW"
    return {
        "id": server.id,
        "name": server.name,
        "hostname": server.hostname,
        "status": "online" if online else "offline",
        "last_seen_at": server.last_seen_at.isoformat() if server.last_seen_at else None,
        "created_at": server.created_at.isoformat(),
        "cpu_percent": latest.cpu_percent if latest else None,
        "memory_percent": latest.memory_percent if latest else None,
        "tcp_connections": latest.tcp_connections if latest else 0,
        "udp_connections": latest.udp_connections if latest else 0,
        "risk": risk,
    }


def alert_json(alert):
    return {
        "id": alert.id,
        "server_id": alert.server_id,
        "server_name": alert.server.name,
        "severity": alert.severity,
        "title": alert.title,
        "description": alert.description,
        "status": alert.status,
        "first_seen_at": alert.first_seen_at.isoformat(),
        "last_seen_at": alert.last_seen_at.isoformat(),
    }


@api.post("/auth/register")
@limiter.limit("5 per hour")
def register():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error("json_object_required", 400)
    email = data.get("email")
    password = data.get("password")
    if not isinstance(email, str) or len(email.strip()) > 254 or "@" not in email:
        return error("valid_email_required", 400)
    email = email.strip().lower()
    if not password_is_valid(password):
        return error("password_must_be_12_to_128_characters", 400)
    if User.query.filter(func.lower(User.email) == email).first():
        return error("email_already_registered", 409)

    user = User(email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    session.clear()
    session["user_id"] = user.id
    session.permanent = True
    return jsonify(id=user.id, email=user.email), 201


@api.post("/auth/login")
@limiter.limit("10 per minute")
def login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error("json_object_required", 400)
    email = data.get("email")
    password = data.get("password")
    user = User.query.filter(func.lower(User.email) == email.strip().lower()).first() if isinstance(email, str) else None
    if not user or not isinstance(password, str) or not check_password_hash(user.password_hash, password):
        return error("invalid_credentials", 401)
    session.clear()
    session["user_id"] = user.id
    session.permanent = True
    return jsonify(id=user.id, email=user.email)


@api.post("/auth/logout")
@login_required
def logout():
    session.clear()
    return jsonify(message="logged_out")


@api.get("/auth/me")
@login_required
def me():
    user = current_user()
    return jsonify(id=user.id, email=user.email, created_at=user.created_at.isoformat())


@api.get("/dashboard")
@login_required
def dashboard():
    now = utcnow()
    servers = Server.query.filter_by(owner_id=session["user_id"]).order_by(Server.id).all()
    server_rows = []
    connection_total = 0
    tcp_total = 0
    udp_total = 0
    for server in servers:
        latest = MetricSnapshot.query.filter_by(server_id=server.id).order_by(MetricSnapshot.recorded_at.desc()).first()
        server_rows.append(server_json(server, latest, now))
        if latest:
            tcp_total += latest.tcp_connections
            udp_total += latest.udp_connections
            connection_total += latest.tcp_connections + latest.udp_connections
    alerts = (
        Alert.query.join(Server)
        .filter(Server.owner_id == session["user_id"], Alert.status == "active")
        .order_by(Alert.last_seen_at.desc())
        .limit(20)
        .all()
    )
    snapshots = (
        MetricSnapshot.query.join(Server)
        .filter(Server.owner_id == session["user_id"])
        .order_by(MetricSnapshot.recorded_at.desc())
        .limit(60)
        .all()
    )
    return jsonify(
        servers=server_rows,
        summary={
            "server_count": len(servers),
            "online_servers": sum(row["status"] == "online" for row in server_rows),
            "tcp_connections": tcp_total,
            "udp_connections": udp_total,
            "connections": connection_total,
            "active_alerts": len(alerts),
        },
        alerts=[alert_json(alert) for alert in alerts],
        traffic=[
            {
                "server_id": snapshot.server_id,
                "recorded_at": snapshot.recorded_at.isoformat(),
                "network_in_bytes": snapshot.network_in_bytes,
                "network_out_bytes": snapshot.network_out_bytes,
            }
            for snapshot in reversed(snapshots)
        ],
    )


@api.get("/servers")
@login_required
def list_servers():
    servers = Server.query.filter_by(owner_id=session["user_id"]).order_by(Server.id).all()
    rows = []
    for server in servers:
        latest = MetricSnapshot.query.filter_by(server_id=server.id).order_by(MetricSnapshot.recorded_at.desc()).first()
        rows.append(server_json(server, latest))
    return jsonify(servers=rows)


@api.post("/servers")
@login_required
def create_server():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error("json_object_required", 400)
    name = data.get("name")
    hostname = data.get("hostname")
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 100:
        return error("server_name_required_max_100_characters", 400)
    if hostname is not None and (not isinstance(hostname, str) or len(hostname) > 255):
        return error("invalid_hostname", 400)

    agent_token = secrets.token_urlsafe(32)
    server = Server(
        owner_id=session["user_id"],
        name=name.strip(),
        hostname=hostname.strip() if hostname else None,
        agent_token_hash=hashlib.sha256(agent_token.encode()).hexdigest(),
    )
    db.session.add(server)
    db.session.commit()
    return jsonify(server=server_json(server), agent_token=agent_token), 201


@api.get("/servers/<int:server_id>")
@login_required
def server_detail(server_id):
    server = owned_server(server_id)
    if not server:
        return error("server_not_found", 404)
    snapshots = (
        MetricSnapshot.query.filter_by(server_id=server.id)
        .order_by(MetricSnapshot.recorded_at.desc())
        .limit(100)
        .all()
    )
    alerts = Alert.query.filter_by(server_id=server.id).order_by(Alert.last_seen_at.desc()).limit(50).all()
    latest = snapshots[0] if snapshots else None
    return jsonify(
        server=server_json(server, latest),
        metrics=[
            {
                "recorded_at": snapshot.recorded_at.isoformat(),
                "cpu_percent": snapshot.cpu_percent,
                "memory_percent": snapshot.memory_percent,
                "tcp_connections": snapshot.tcp_connections,
                "udp_connections": snapshot.udp_connections,
                "network_in_bytes": snapshot.network_in_bytes,
                "network_out_bytes": snapshot.network_out_bytes,
                "failed_ssh_attempts": snapshot.failed_ssh_attempts,
                "listening_ports": snapshot.listening_ports,
                "connections": snapshot.connections,
            }
            for snapshot in reversed(snapshots)
        ],
        alerts=[alert_json(alert) for alert in alerts],
    )


@api.delete("/servers/<int:server_id>")
@login_required
def delete_server(server_id):
    server = owned_server(server_id)
    if not server:
        return error("server_not_found", 404)
    db.session.delete(server)
    db.session.commit()
    return "", 204


@api.get("/alerts")
@login_required
def list_alerts():
    query = Alert.query.join(Server).filter(Server.owner_id == session["user_id"])
    status = request.args.get("status")
    if status in ("active", "resolved"):
        query = query.filter(Alert.status == status)
    alerts = query.order_by(Alert.last_seen_at.desc()).limit(100).all()
    return jsonify(alerts=[alert_json(alert) for alert in alerts])


@api.post("/alerts/<int:alert_id>/resolve")
@login_required
def resolve_alert(alert_id):
    alert = (
        Alert.query.join(Server)
        .filter(Alert.id == alert_id, Server.owner_id == session["user_id"])
        .first()
    )
    if not alert:
        return error("alert_not_found", 404)
    alert.status = "resolved"
    db.session.commit()
    return jsonify(alert=alert_json(alert))


def _number(data, key, default, minimum=0, maximum=None, integer=False):
    value = data.get(key, default)
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or (isinstance(value, float) and not math.isfinite(value))
    ):
        raise ValueError(key)
    if integer and not isinstance(value, int):
        raise ValueError(key)
    if value < minimum or (maximum is not None and value > maximum):
        raise ValueError(key)
    return value


def validate_metrics(data):
    if not isinstance(data, dict):
        raise ValueError("json_object_required")
    cpu = _number(data, "cpu_percent", None, 0, 100)
    memory = _number(data, "memory_percent", None, 0, 100)
    tcp = _number(data, "tcp_connections", 0, 0, 1_000_000, integer=True)
    udp = _number(data, "udp_connections", 0, 0, 1_000_000, integer=True)
    incoming = _number(data, "network_in_bytes", 0, 0, 9_223_372_036_854_775_807, integer=True)
    outgoing = _number(data, "network_out_bytes", 0, 0, 9_223_372_036_854_775_807, integer=True)
    ssh_failures = _number(data, "failed_ssh_attempts", 0, 0, 1_000_000, integer=True)
    ports = data.get("listening_ports", [])
    connections = data.get("connections", [])
    if not isinstance(ports, list) or len(ports) > 4096:
        raise ValueError("listening_ports")
    if any(isinstance(port, bool) or not isinstance(port, int) or port < 1 or port > 65535 for port in ports):
        raise ValueError("listening_ports")
    if not isinstance(connections, list) or len(connections) > 500:
        raise ValueError("connections")
    safe_connections = []
    for item in connections:
        if not isinstance(item, dict):
            raise ValueError("connections")
        safe = {}
        for key in ("process", "remote_ip", "remote_port", "protocol", "status"):
            value = item.get(key)
            if value is not None and (not isinstance(value, (str, int)) or len(str(value)) > 128):
                raise ValueError("connections")
            safe[key] = value
        safe_connections.append(safe)
    return {
        "cpu_percent": cpu,
        "memory_percent": memory,
        "tcp_connections": tcp,
        "udp_connections": udp,
        "network_in_bytes": incoming,
        "network_out_bytes": outgoing,
        "failed_ssh_attempts": ssh_failures,
        "listening_ports": sorted(set(ports)),
        "connections": safe_connections,
    }


def record_alert(server, rule_key, severity, title, description):
    alert = Alert.query.filter_by(server_id=server.id, rule_key=rule_key, status="active").first()
    now = utcnow()
    if alert:
        alert.description = description
        alert.last_seen_at = now
        return
    db.session.add(
        Alert(
            server_id=server.id,
            rule_key=rule_key,
            severity=severity,
            title=title,
            description=description,
            first_seen_at=now,
            last_seen_at=now,
        )
    )


def detect_anomalies(server, metrics, previous):
    if metrics["failed_ssh_attempts"] >= SSH_FAILURE_THRESHOLD:
        record_alert(
            server,
            "ssh_failures",
            "high",
            "Repeated failed SSH logins",
            f"The agent reported {metrics['failed_ssh_attempts']} failed SSH attempts in its latest interval.",
        )
    previous_ports = set(previous.listening_ports) if previous else set()
    new_ports = sorted(set(metrics["listening_ports"]) - previous_ports) if previous else []
    for port in new_ports:
        record_alert(
            server,
            f"new_listening_port:{port}",
            "medium",
            "New listening port detected",
            f"Port {port} is listening but was not present in the previous report.",
        )
    recent = (
        MetricSnapshot.query.filter_by(server_id=server.id)
        .order_by(MetricSnapshot.recorded_at.desc())
        .limit(10)
        .all()
    )
    if len(recent) >= 3:
        baseline = sum(item.network_in_bytes + item.network_out_bytes for item in recent) / len(recent)
        current_traffic = metrics["network_in_bytes"] + metrics["network_out_bytes"]
        if current_traffic >= TRAFFIC_SPIKE_FLOOR and current_traffic >= baseline * TRAFFIC_SPIKE_MULTIPLIER:
            record_alert(
                server,
                "traffic_spike",
                "medium",
                "Unusual network traffic spike",
                f"Traffic in the latest reporting interval was {current_traffic} bytes, at least "
                f"{TRAFFIC_SPIKE_MULTIPLIER}x the recent average of {int(baseline)} bytes.",
            )
@api.post("/agent/heartbeat")
@csrf.exempt
@limiter.limit("120 per minute")
def agent_heartbeat():
    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return error("agent_token_required", 401)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    server = Server.query.filter_by(agent_token_hash=token_hash).first()
    if not server or not hmac.compare_digest(server.agent_token_hash, token_hash):
        return error("invalid_agent_token", 401)
    data = request.get_json(silent=True)
    try:
        metrics = validate_metrics(data)
    except (ValueError, TypeError):
        return error("invalid_metrics_payload", 400)

    previous = MetricSnapshot.query.filter_by(server_id=server.id).order_by(MetricSnapshot.recorded_at.desc()).first()
    snapshot = MetricSnapshot(server_id=server.id, **metrics)
    server.last_seen_at = utcnow()
    detect_anomalies(server, metrics, previous)
    db.session.add(snapshot)
    db.session.commit()
    return jsonify(accepted=True, received_at=snapshot.recorded_at.isoformat()), 202
