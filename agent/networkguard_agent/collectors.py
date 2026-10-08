import json
import logging
import re
import socket
import subprocess

import psutil

logger = logging.getLogger(__name__)
SSH_FAILURE = re.compile(r"(?:failed password|authentication failure|invalid user)", re.IGNORECASE)


class MetricsCollector:
    def __init__(self):
        self.previous_network = psutil.net_io_counters()

    @staticmethod
    def _connection_detail(connection):
        remote = connection.raddr
        if not remote:
            return None
        local = connection.laddr
        try:
            process = psutil.Process(connection.pid).name() if connection.pid else None
        except (psutil.Error, OSError):
            process = None
        protocol = "tcp" if connection.type == 1 else "udp"
        return {
            "process": process,
            "pid": connection.pid,
            "local_ip": str(local.ip) if local else None,
            "local_port": local.port if local else None,
            "remote_ip": str(remote.ip),
            "remote_port": remote.port,
            "protocol": protocol,
            "status": connection.status or "UNKNOWN",
        }

    @staticmethod
    def _failed_ssh_attempts(interval_seconds):
        try:
            result = subprocess.run(
                [
                    "journalctl",
                    "--since",
                    f"{interval_seconds} seconds ago",
                    "--no-pager",
                    "--output=json",
                    "-n",
                    "5000",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("Could not read recent SSH login events from journald: %s", exc)
            return 0
        if result.returncode != 0:
            logger.warning("journalctl could not read recent logs: %s", result.stderr.strip()[:300])
            return 0

        failures = 0
        for line in result.stdout.splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Ignoring malformed JSON entry returned by journalctl")
                continue
            if not isinstance(entry, dict):
                logger.warning("Ignoring non-object entry returned by journalctl")
                continue
            if entry.get("SYSLOG_IDENTIFIER") != "sshd" and entry.get("_COMM") != "sshd":
                continue
            message = entry.get("MESSAGE", "")
            if isinstance(message, str) and SSH_FAILURE.search(message):
                failures += 1
        return failures

    def collect(self, interval_seconds):
        current_network = psutil.net_io_counters()
        network_in = max(0, current_network.bytes_recv - self.previous_network.bytes_recv)
        network_out = max(0, current_network.bytes_sent - self.previous_network.bytes_sent)
        self.previous_network = current_network

        tcp_connections = 0
        udp_connections = 0
        listening_ports = set()
        active_connections = []
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.Error, OSError) as exc:
            logger.warning("Could not inspect network connections (try running as root): %s", exc)
            connections = []

        for connection in connections:
            if connection.type == socket.SOCK_STREAM:
                tcp_connections += 1
                if connection.status == psutil.CONN_LISTEN and connection.laddr:
                    listening_ports.add(connection.laddr.port)
                elif connection.status == psutil.CONN_ESTABLISHED and connection.raddr:
                    detail = self._connection_detail(connection)
                    if detail:
                        active_connections.append(detail)
            elif connection.type == socket.SOCK_DGRAM:
                udp_connections += 1
                if connection.laddr:
                    listening_ports.add(connection.laddr.port)

        active_connections.sort(key=lambda item: (item["remote_ip"], item["remote_port"]))
        return {
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "memory_percent": psutil.virtual_memory().percent,
            "tcp_connections": tcp_connections,
            "udp_connections": udp_connections,
            "network_in_bytes": network_in,
            "network_out_bytes": network_out,
            "failed_ssh_attempts": self._failed_ssh_attempts(interval_seconds),
            "listening_ports": sorted(listening_ports),
            "connections": active_connections[:500],
        }
