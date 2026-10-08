import argparse
import json
import logging
import os
import signal
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from .collectors import MetricsCollector

logger = logging.getLogger("networkguard_agent")
HEARTBEAT_PATH = "/api/agent/heartbeat"


def load_config(environ=None):
    environ = environ or os.environ
    base_url = environ.get("NETWORKGUARD_URL", "").strip().rstrip("/")
    token = environ.get("NETWORKGUARD_TOKEN", "").strip()
    if not base_url or not token:
        raise ValueError("Set NETWORKGUARD_URL and NETWORKGUARD_TOKEN.")
    parsed = urlparse(base_url)
    is_loopback = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme != "https" and not is_loopback:
        raise ValueError("NETWORKGUARD_URL must use HTTPS except for loopback development.")
    if (
        parsed.scheme not in ("https", "http")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or (parsed.scheme == "http" and parsed.path not in ("", "/"))
    ):
        raise ValueError("NETWORKGUARD_URL must be a valid base URL without credentials or query parameters.")
    try:
        interval = int(environ.get("NETWORKGUARD_INTERVAL", "60"))
    except ValueError as exc:
        raise ValueError("NETWORKGUARD_INTERVAL must be an integer of at least 10 seconds.") from exc
    if interval < 10 or interval > 3600:
        raise ValueError("NETWORKGUARD_INTERVAL must be between 10 and 3600 seconds.")
    return f"{base_url}{HEARTBEAT_PATH}", token, interval


def send_heartbeat(url, token, metrics, timeout=15):
    body = json.dumps(metrics, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "NetworkGuard-Agent/0.1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read(1024)
            if response.status != 202:
                raise RuntimeError(f"Backend returned unexpected HTTP status {response.status}.")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Backend rejected the heartbeat with HTTP {exc.code}.") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not connect to the backend: {exc.reason}.") from exc


def run(once=False):
    try:
        url, token, interval = load_config()
    except ValueError as exc:
        logger.error("%s", exc)
        return 2

    stop = False

    def request_stop(_signum, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    collector = MetricsCollector()
    if once:
        try:
            time.sleep(interval)
            send_heartbeat(url, token, collector.collect(interval))
            logger.info("One-time heartbeat accepted.")
            return 0
        except (OSError, RuntimeError) as exc:
            logger.error("One-time heartbeat failed: %s", exc)
            return 1

    logger.info("Starting NetworkGuard agent; heartbeat interval is %s seconds.", interval)
    next_sample_at = time.monotonic() + interval

    while not stop:
        time.sleep(max(0, next_sample_at - time.monotonic()))
        if stop:
            break
        started = time.monotonic()
        try:
            metrics = collector.collect(interval)
            send_heartbeat(url, token, metrics)
            logger.info("Heartbeat accepted.")
        except (OSError, RuntimeError) as exc:
            logger.error("Heartbeat failed: %s", exc)
        next_sample_at = max(next_sample_at + interval, started + interval)
    logger.info("NetworkGuard agent stopped.")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Collect Linux metrics and send NetworkGuard heartbeats.")
    parser.add_argument("--version", action="version", version="NetworkGuard Agent 0.1.0")
    parser.add_argument(
        "--once",
        action="store_true",
        help="collect and send one heartbeat, then exit",
    )
    args = parser.parse_args()
    logging.basicConfig(
        level=os.environ.get("NETWORKGUARD_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    raise SystemExit(run(once=args.once))


if __name__ == "__main__":
    main()
