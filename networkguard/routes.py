import hashlib
import hmac
import ipaddress
import math
import secrets
from datetime import timedelta
from functools import wraps

from flask import Blueprint, jsonify, request, session
from sqlalchemy import func
from werkzeug.security import check_password_hash

from . import csrf
from .extensions import db, limiter
from .models import (
    Alert,
    IPRule,
    MetricSnapshot,
    SecurityEvent,
    Server,
    User,
    password_is_valid,
    utcnow,
)

api = Blueprint("api", __name__)
ONLINE_WINDOW = timedelta(seconds=90)
SSH_FAILURE_THRESHOLD = 5
TRAFFIC_SPIKE_FLOOR = 10 * 1024 * 1024
TRAFFIC_SPIKE_MULTIPLIER = 4
HIGH_CONNECTION_THRESHOLD = 80
COMMON_REMOTE_PORTS = {22, 53, 80, 123, 443, 853}


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


def event_json(event):
    return {
        "id": event.id,
        "server_id": event.server_id,
        "server_name": event.server.name,
        "kind": event.kind,
        "severity": event.severity,
        "title": event.title,
        "details": event.details,
        "status": event.status,
        "occurrences": event.occurrences,
        "first_seen_at": event.first_seen_at.isoformat(),
        "last_seen_at": event.last_seen_at.isoformat(),
    }


def ip_rule_json(rule):
    return {
        "id": rule.id,
        "server_id": rule.server_id,
        "ip_address": rule.ip_address,
        "action": rule.action,
        "note": rule.note,
        "created_at": rule.created_at.isoformat(),
    }


def known_remote_ips(server, snapshots=None):
    snapshots = snapshots if snapshots is not None else (
        MetricSnapshot.query.filter_by(server_id=server.id)
        .order_by(MetricSnapshot.recorded_at.desc())
        .limit(10)
        .all()
    )
    return {
        connection.get("remote_ip")
        for snapshot in snapshots
        for connection in (snapshot.connections or [])
        if connection.get("remote_ip")
    }


def classify_connections(server, connections, known_ips=None, rules=None):
    known_ips = known_ips if known_ips is not None else known_remote_ips(server)
    rules = rules if rules is not None else {
        rule.ip_address: rule.action
        for rule in IPRule.query.filter_by(server_id=server.id).all()
    }
    classified = []
    for connection in connections or []:
        remote_ip = connection.get("remote_ip")
        action = rules.get(remote_ip)
        if action == "block":
            risk, reason = "listed_to_block", "On your informational blocklist; traffic is not blocked."
        elif action == "allow":
            risk, reason = "allowed", "On your allowlist."
        elif not connection.get("process"):
            risk, reason = "unknown_process", "The agent could not identify this connection's process."
        elif remote_ip and remote_ip not in known_ips:
            risk, reason = "new_ip", "First observed remote IP; review if unexpected."
        else:
            risk, reason = "normal", "Previously observed connection."
        classified.append({**connection, "risk": risk, "risk_reason": reason})
    return classified


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
    suspicious_connections = 0
    listed_connections = 0
    normal_connections = 0
    process_counts = {}
    for server in servers:
        recent_server_snapshots = (
            MetricSnapshot.query.filter_by(server_id=server.id)
            .order_by(MetricSnapshot.recorded_at.desc())
            .limit(11)
            .all()
        )
        latest = recent_server_snapshots[0] if recent_server_snapshots else None
        server_rows.append(server_json(server, latest, now))
        if latest:
            tcp_total += latest.tcp_connections
            udp_total += latest.udp_connections
            connection_total += latest.tcp_connections + latest.udp_connections
            latest_connections = classify_connections(
                server,
                latest.connections,
                known_ips=known_remote_ips(server, recent_server_snapshots[1:]),
            )
            suspicious_connections += sum(
                item["risk"] in ("new_ip", "unknown_process") for item in latest_connections
            )
            listed_connections += sum(item["risk"] == "listed_to_block" for item in latest_connections)
            normal_connections += sum(item["risk"] in ("normal", "allowed") for item in latest_connections)
            for item in latest_connections:
                process = item.get("process")
                if process:
                    process_counts[process] = process_counts.get(process, 0) + 1
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
    events = (
        SecurityEvent.query.join(Server)
        .filter(Server.owner_id == session["user_id"])
        .order_by(SecurityEvent.last_seen_at.desc())
        .limit(30)
        .all()
    )
    active_event_count = (
        SecurityEvent.query.join(Server)
        .filter(Server.owner_id == session["user_id"], SecurityEvent.status == "active")
        .count()
    )
    rule_counts = dict(
        db.session.query(IPRule.action, func.count(IPRule.id))
        .join(Server)
        .filter(Server.owner_id == session["user_id"])
        .group_by(IPRule.action)
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
            "active_events": active_event_count,
            "suspicious_connections": suspicious_connections,
            "listed_connections": listed_connections,
            "normal_connections": normal_connections,
            "blocked_ips": rule_counts.get("block", 0),
            "allowed_ips": rule_counts.get("allow", 0),
        },
        alerts=[alert_json(alert) for alert in alerts],
        events=[event_json(event) for event in events],
        top_processes=[
            {"process": process, "connections": count}
            for process, count in sorted(process_counts.items(), key=lambda item: (-item[1], item[0]))[:10]
        ],
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
    rules = IPRule.query.filter_by(server_id=server.id).order_by(IPRule.action, IPRule.ip_address).all()
    events = SecurityEvent.query.filter_by(server_id=server.id).order_by(SecurityEvent.last_seen_at.desc()).limit(100).all()
    recent_ips = known_remote_ips(server, snapshots[1:])
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
                "connections": classify_connections(
                    server,
                    snapshot.connections,
                    known_ips=recent_ips,
                    rules={rule.ip_address: rule.action for rule in rules},
                ),
            }
            for snapshot in reversed(snapshots)
        ],
        alerts=[alert_json(alert) for alert in alerts],
        events=[event_json(event) for event in events],
        ip_rules=[ip_rule_json(rule) for rule in rules],
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


@api.get("/events")
@login_required
def list_events():
    query = SecurityEvent.query.join(Server).filter(Server.owner_id == session["user_id"])
    status = request.args.get("status")
    if status in ("active", "resolved"):
        query = query.filter(SecurityEvent.status == status)
    events = query.order_by(SecurityEvent.last_seen_at.desc()).limit(200).all()
    return jsonify(events=[event_json(event) for event in events])


@api.post("/events/<int:event_id>/resolve")
@login_required
def resolve_event(event_id):
    event = (
        SecurityEvent.query.join(Server)
        .filter(SecurityEvent.id == event_id, Server.owner_id == session["user_id"])
        .first()
    )
    if not event:
        return error("event_not_found", 404)
    event.status = "resolved"
    db.session.commit()
    return jsonify(event=event_json(event))


@api.get("/servers/<int:server_id>/ip-rules")
@login_required
def list_ip_rules(server_id):
    server = owned_server(server_id)
    if not server:
        return error("server_not_found", 404)
    rules = IPRule.query.filter_by(server_id=server.id).order_by(IPRule.action, IPRule.ip_address).all()
    return jsonify(ip_rules=[ip_rule_json(rule) for rule in rules], enforcement="informational_only")


@api.post("/servers/<int:server_id>/ip-rules")
@login_required
def create_ip_rule(server_id):
    server = owned_server(server_id)
    if not server:
        return error("server_not_found", 404)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error("json_object_required", 400)
    address = data.get("ip_address")
    action = data.get("action")
    note = data.get("note", "")
    if not isinstance(address, str):
        return error("valid_ip_address_required", 400)
    try:
        address = str(ipaddress.ip_address(address.strip()))
    except ValueError:
        return error("valid_ip_address_required", 400)
    if action not in ("allow", "block"):
        return error("action_must_be_allow_or_block", 400)
    if not isinstance(note, str) or len(note.strip()) > 200:
        return error("note_must_be_200_characters_or_less", 400)
    existing = IPRule.query.filter_by(server_id=server.id, ip_address=address).first()
    if existing:
        existing.action = action
        existing.note = note.strip()
        rule = existing
    else:
        rule = IPRule(server_id=server.id, ip_address=address, action=action, note=note.strip())
        db.session.add(rule)
    db.session.commit()
    return jsonify(ip_rule=ip_rule_json(rule), enforcement="informational_only"), 201


@api.delete("/servers/<int:server_id>/ip-rules/<int:rule_id>")
@login_required
def delete_ip_rule(server_id, rule_id):
    rule = (
        IPRule.query.join(Server)
        .filter(
            IPRule.id == rule_id,
            IPRule.server_id == server_id,
            Server.owner_id == session["user_id"],
        )
        .first()
    )
    if not rule:
        return error("ip_rule_not_found", 404)
    db.session.delete(rule)
    db.session.commit()
    return "", 204


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
        for key in (
            "process",
            "pid",
            "local_ip",
            "local_port",
            "remote_ip",
            "remote_port",
            "protocol",
            "status",
        ):
            value = item.get(key)
            if key in ("pid", "local_port", "remote_port"):
                if value is not None and (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value < 0
                    or value > 2**31 - 1
                ):
                    raise ValueError("connections")
            elif value is not None and (not isinstance(value, str) or len(value) > 128):
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


def record_event(server, event_key, kind, severity, title, details):
    event = SecurityEvent.query.filter_by(
        server_id=server.id,
        event_key=event_key,
        status="active",
    ).first()
    now = utcnow()
    if event:
        event.details = details[:500]
        event.last_seen_at = now
        event.occurrences += 1
        return
    db.session.add(
        SecurityEvent(
            server_id=server.id,
            event_key=event_key[:180],
            kind=kind,
            severity=severity,
            title=title[:160],
            details=details[:500],
            first_seen_at=now,
            last_seen_at=now,
        )
    )


def detect_anomalies(server, metrics, previous):
    if metrics["failed_ssh_attempts"] >= SSH_FAILURE_THRESHOLD:
        details = f"{metrics['failed_ssh_attempts']} failed SSH attempts were reported in the latest interval."
        record_event(server, "ssh_failures", "ssh", "high", "Repeated failed SSH logins", details)
        record_alert(
            server,
            "ssh_failures",
            "high",
            "Repeated failed SSH logins",
            details,
        )
    previous_ports = set(previous.listening_ports) if previous else set()
    new_ports = sorted(set(metrics["listening_ports"]) - previous_ports) if previous else []
    for port in new_ports:
        details = f"Listening port {port} appeared since the previous report."
        record_event(server, f"new_listening_port:{port}", "port", "medium", "New listening port detected", details)
        record_alert(
            server,
            f"new_listening_port:{port}",
            "medium",
            "New listening port detected",
            details,
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
            details = (
                f"Latest interval: {current_traffic} bytes; recent average: {int(baseline)} bytes."
            )
            record_event(server, "traffic_spike", "traffic", "medium", "Unusual network traffic spike", details)
            record_alert(
                server,
                "traffic_spike",
                "medium",
                "Unusual network traffic spike",
                f"Traffic in the latest reporting interval was {current_traffic} bytes, at least "
                f"{TRAFFIC_SPIKE_MULTIPLIER}x the recent average of {int(baseline)} bytes.",
            )
    if metrics["tcp_connections"] + metrics["udp_connections"] >= HIGH_CONNECTION_THRESHOLD:
        total = metrics["tcp_connections"] + metrics["udp_connections"]
        record_event(
            server,
            "high_connection_count",
            "connections",
            "high",
            "High connection count",
            f"The latest report contains {total} TCP and UDP connections.",
        )

    if previous:
        previous_ips = known_remote_ips(
            server,
            MetricSnapshot.query.filter_by(server_id=server.id)
            .order_by(MetricSnapshot.recorded_at.desc())
            .limit(10)
            .all(),
        )
        rules = {
            rule.ip_address: rule.action
            for rule in IPRule.query.filter_by(server_id=server.id).all()
        }
        for connection in metrics["connections"]:
            remote_ip = connection.get("remote_ip")
            if not remote_ip or rules.get(remote_ip) in ("allow", "block"):
                continue
            if remote_ip not in previous_ips:
                record_event(
                    server,
                    f"new_remote_ip:{remote_ip}",
                    "ip",
                    "low",
                    "New remote IP observed",
                    f"{connection.get('process') or 'Unknown process'} connected to {remote_ip}:"
                    f"{connection.get('remote_port') or 'unknown'}. This is a first-seen address, "
                    "not proof of malicious activity.",
                )
            if not connection.get("process"):
                record_event(
                    server,
                    f"unknown_process:{remote_ip}",
                    "process",
                    "low",
                    "Connection process unavailable",
                    f"The agent could not identify the process connected to {remote_ip}. "
                    "This can happen when process access is restricted.",
                )
            remote_port = connection.get("remote_port")
            if remote_port and remote_port not in COMMON_REMOTE_PORTS:
                process = connection.get("process") or "unknown"
                record_event(
                    server,
                    f"unusual_remote_port:{remote_port}:{process}",
                    "port",
                    "low",
                    "Connection uses an uncommon remote port",
                    f"{process} connected to {remote_ip}:{remote_port}. Review this if unexpected; "
                    "uncommon ports are not automatically malicious.",
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
