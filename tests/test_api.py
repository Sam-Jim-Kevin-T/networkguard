import unittest
from unittest.mock import patch
import os

from networkguard import create_app, database_uri_from_env
from networkguard.extensions import db


class ApiTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-only-secret",
                "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
                "WTF_CSRF_ENABLED": False,
                "RATELIMIT_ENABLED": False,
            }
        )
        self.client = self.app.test_client()
        with self.app.app_context():
            db.drop_all()
            db.create_all()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
            db.engine.dispose()

    def register(self, email):
        return self.client.post(
            "/api/auth/register",
            json={"email": email, "password": "correct-horse-battery"},
        )

    def create_server(self, name="Test server"):
        response = self.client.post("/api/servers", json={"name": name})
        self.assertEqual(response.status_code, 201)
        return response.get_json()

    @staticmethod
    def metrics(**overrides):
        data = {
            "cpu_percent": 12.5,
            "memory_percent": 45.0,
            "tcp_connections": 2,
            "udp_connections": 1,
            "network_in_bytes": 4096,
            "network_out_bytes": 8192,
            "failed_ssh_attempts": 0,
            "listening_ports": [22, 443],
            "connections": [
                {
                    "process": "nginx",
                    "remote_ip": "203.0.113.7",
                    "remote_port": 443,
                    "protocol": "tcp",
                    "status": "ESTABLISHED",
                }
            ],
        }
        data.update(overrides)
        return data

    def test_registration_requires_strong_password_and_logs_user_in(self):
        response = self.client.post(
            "/api/auth/register",
            json={"email": "person@example.com", "password": "short"},
        )
        self.assertEqual(response.status_code, 400)

        response = self.register("Person@Example.com")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.get_json()["email"], "person@example.com")
        self.assertEqual(self.client.get("/api/auth/me").status_code, 200)

    def test_user_mutations_require_csrf_token(self):
        app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "csrf-test-secret",
                "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
                "RATELIMIT_ENABLED": False,
            }
        )
        client = app.test_client()
        denied = client.post(
            "/api/auth/register",
            json={"email": "csrf@example.com", "password": "correct-horse-battery"},
        )
        self.assertEqual(denied.status_code, 400)

        token = client.get("/api/csrf").get_json()["csrf_token"]
        accepted = client.post(
            "/api/auth/register",
            headers={"X-CSRFToken": token},
            json={"email": "csrf@example.com", "password": "correct-horse-battery"},
        )
        self.assertEqual(accepted.status_code, 201)
        with app.app_context():
            db.session.remove()
            db.engine.dispose()

    def test_landing_page_serves_dashboard_assets(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"NetworkGuard", response.data)
        self.assertIn(b"/static/app.js", response.data)
        script = self.client.get("/static/app.js")
        self.assertEqual(script.status_code, 200)
        self.assertTrue(script.get_data())
        script.close()
        stylesheet = self.client.get("/static/app.css")
        self.assertEqual(stylesheet.status_code, 200)
        self.assertTrue(stylesheet.get_data())
        stylesheet.close()

    def test_postgres_provider_urls_use_psycopg_driver(self):
        self.assertEqual(
            database_uri_from_env("postgres://user:pass@db.example/app"),
            "postgresql+psycopg://user:pass@db.example/app",
        )
        self.assertEqual(
            database_uri_from_env("postgresql://user:pass@db.example/app"),
            "postgresql+psycopg://user:pass@db.example/app",
        )
        self.assertEqual(database_uri_from_env("sqlite:///local.db"), "sqlite:///local.db")

    def test_render_refuses_ephemeral_sqlite_database(self):
        with patch.dict(os.environ, {"RENDER": "true", "DATABASE_URL": "sqlite:///local.db"}):
            with self.assertRaisesRegex(RuntimeError, "persistent PostgreSQL"):
                create_app(
                    {
                        "SECRET_KEY": "deployment-test-secret",
                        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
                    }
                )

    def test_health_check_confirms_database_is_reachable(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"status": "ok"})
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        secure_response = self.client.get("/healthz", base_url="https://localhost")
        self.assertEqual(
            secure_response.headers["Strict-Transport-Security"],
            "max-age=31536000",
        )

    def test_server_data_is_private_to_owner(self):
        self.register("owner@example.com")
        created = self.create_server()
        server_id = created["server"]["id"]
        self.client.post(
            "/api/agent/heartbeat",
            headers={"Authorization": f"Bearer {created['agent_token']}"},
            json=self.metrics(),
        )
        self.client.post("/api/auth/logout")
        self.register("other@example.com")

        self.assertEqual(self.client.get(f"/api/servers/{server_id}").status_code, 404)
        self.assertEqual(self.client.delete(f"/api/servers/{server_id}").status_code, 404)
        self.assertEqual(self.client.get("/api/servers").get_json()["servers"], [])
        self.assertEqual(self.client.get("/api/dashboard").get_json()["summary"]["server_count"], 0)

    def test_agent_token_ingests_metrics_and_generates_alerts(self):
        self.register("agent-owner@example.com")
        created = self.create_server()
        token = created["agent_token"]
        heartbeat_url = "/api/agent/heartbeat"
        headers = {"Authorization": f"Bearer {token}"}

        self.assertEqual(
            self.client.post(heartbeat_url, headers={"Authorization": "Bearer invalid"}, json=self.metrics()).status_code,
            401,
        )
        first = self.client.post(heartbeat_url, headers=headers, json=self.metrics())
        self.assertEqual(first.status_code, 202)
        second = self.client.post(
            heartbeat_url,
            headers=headers,
            json=self.metrics(listening_ports=[22, 443, 8081], failed_ssh_attempts=6),
        )
        self.assertEqual(second.status_code, 202)

        detail = self.client.get(f"/api/servers/{created['server']['id']}").get_json()
        self.assertEqual(detail["metrics"][-1]["cpu_percent"], 12.5)
        self.assertEqual(
            {alert["title"] for alert in detail["alerts"]},
            {"Repeated failed SSH logins", "New listening port detected"},
        )
        self.assertEqual(self.client.get("/api/dashboard").get_json()["summary"]["active_alerts"], 2)
        self.assertEqual(detail["server"]["risk"], "HIGH")

    def test_agent_rejects_invalid_metrics(self):
        self.register("validation@example.com")
        created = self.create_server()
        response = self.client.post(
            "/api/agent/heartbeat",
            headers={"Authorization": f"Bearer {created['agent_token']}"},
            json=self.metrics(cpu_percent=101),
        )
        self.assertEqual(response.status_code, 400)
        oversized_integer = self.client.post(
            "/api/agent/heartbeat",
            headers={"Authorization": f"Bearer {created['agent_token']}"},
            json=self.metrics(tcp_connections=10**1000),
        )
        self.assertEqual(oversized_integer.status_code, 400)

    def test_alerts_can_be_resolved_by_owner(self):
        self.register("alerts@example.com")
        created = self.create_server()
        headers = {"Authorization": f"Bearer {created['agent_token']}"}
        for payload in (
            self.metrics(),
            self.metrics(failed_ssh_attempts=6),
        ):
            self.client.post("/api/agent/heartbeat", headers=headers, json=payload)
        alert = self.client.get("/api/alerts").get_json()["alerts"][0]
        response = self.client.post(f"/api/alerts/{alert['id']}/resolve")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["alert"]["status"], "resolved")
        self.assertEqual(self.client.get("/api/alerts?status=active").get_json()["alerts"], [])

    def test_traffic_spike_is_detected_after_baseline_reports(self):
        self.register("traffic@example.com")
        created = self.create_server()
        headers = {"Authorization": f"Bearer {created['agent_token']}"}
        for _ in range(3):
            response = self.client.post("/api/agent/heartbeat", headers=headers, json=self.metrics())
            self.assertEqual(response.status_code, 202)

        response = self.client.post(
            "/api/agent/heartbeat",
            headers=headers,
            json=self.metrics(network_in_bytes=20 * 1024 * 1024),
        )
        self.assertEqual(response.status_code, 202)
        alerts = self.client.get("/api/alerts").get_json()["alerts"]
        self.assertIn("Unusual network traffic spike", {alert["title"] for alert in alerts})


if __name__ == "__main__":
    unittest.main()
