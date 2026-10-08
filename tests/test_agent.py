import unittest
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))

from networkguard_agent.agent import load_config, run
from networkguard_agent.collectors import MetricsCollector


class AgentConfigTests(unittest.TestCase):
    def test_loads_secure_endpoint_and_interval(self):
        config = load_config(
            {
                "NETWORKGUARD_URL": "https://monitor.example.com/",
                "NETWORKGUARD_TOKEN": "secret-token",
                "NETWORKGUARD_INTERVAL": "30",
            }
        )
        self.assertEqual(
            config,
            ("https://monitor.example.com/api/agent/heartbeat", "secret-token", 30),
        )

    def test_rejects_public_http_endpoint(self):
        with self.assertRaisesRegex(ValueError, "must use HTTPS"):
            load_config(
                {
                    "NETWORKGUARD_URL": "http://monitor.example.com",
                    "NETWORKGUARD_TOKEN": "secret-token",
                }
            )

    def test_rejects_http_host_only_url(self):
        with self.assertRaisesRegex(ValueError, "must use HTTPS"):
            load_config(
                {
                    "NETWORKGUARD_URL": "http://192.168.148.1:5000",
                    "NETWORKGUARD_TOKEN": "secret-token",
                }
            )

    def test_rejects_short_interval(self):
        with self.assertRaisesRegex(ValueError, "between 10 and 3600"):
            load_config(
                {
                    "NETWORKGUARD_URL": "http://localhost:5000",
                    "NETWORKGUARD_TOKEN": "secret-token",
                    "NETWORKGUARD_INTERVAL": "5",
                }
            )


class AgentRunTests(unittest.TestCase):
    @patch.dict(
        "os.environ",
        {
            "NETWORKGUARD_URL": "http://127.0.0.1:5000",
            "NETWORKGUARD_TOKEN": "local-test-token",
            "NETWORKGUARD_INTERVAL": "10",
        },
        clear=True,
    )
    @patch("networkguard_agent.agent.send_heartbeat")
    @patch("networkguard_agent.agent.MetricsCollector")
    @patch("networkguard_agent.agent.time.sleep")
    def test_once_sends_a_heartbeat_and_exits(self, sleep, collector_class, send_heartbeat):
        collector_class.return_value.collect.return_value = {"cpu_percent": 10}
        self.assertEqual(run(once=True), 0)
        sleep.assert_called_once_with(10)
        collector_class.return_value.collect.assert_called_once_with(10)
        send_heartbeat.assert_called_once_with(
            "http://127.0.0.1:5000/api/agent/heartbeat",
            "local-test-token",
            {"cpu_percent": 10},
        )


class MetricsCollectorTests(unittest.TestCase):
    @patch("networkguard_agent.collectors.subprocess.run")
    @patch("networkguard_agent.collectors.psutil.net_connections")
    @patch("networkguard_agent.collectors.psutil.virtual_memory")
    @patch("networkguard_agent.collectors.psutil.cpu_percent")
    @patch("networkguard_agent.collectors.psutil.net_io_counters")
    def test_collects_backend_compatible_metrics(
        self, counters, cpu, memory, connections, journal
    ):
        counters.side_effect = [
            SimpleNamespace(bytes_recv=100, bytes_sent=200),
            SimpleNamespace(bytes_recv=350, bytes_sent=450),
        ]
        cpu.return_value = 12.5
        memory.return_value = SimpleNamespace(percent=42.0)
        connections.return_value = [
            SimpleNamespace(
                type=1,
                status="LISTEN",
                laddr=SimpleNamespace(port=22),
                raddr=(),
                pid=None,
            ),
            SimpleNamespace(
                type=1,
                status="ESTABLISHED",
                laddr=SimpleNamespace(ip="192.168.1.10", port=40000),
                raddr=SimpleNamespace(ip="203.0.113.8", port=443),
                pid=None,
            ),
            SimpleNamespace(
                type=2,
                status="NONE",
                laddr=SimpleNamespace(port=5353),
                raddr=(),
                pid=None,
            ),
        ]
        journal.return_value = SimpleNamespace(
            returncode=0,
            stderr="",
            stdout=(
                '{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for user"}\n'
                '{"SYSLOG_IDENTIFIER":"kernel","MESSAGE":"Failed password unrelated"}\n'
            ),
        )
        collector = MetricsCollector()
        result = collector.collect(60)

        self.assertEqual(result["cpu_percent"], 12.5)
        self.assertEqual(result["memory_percent"], 42.0)
        self.assertEqual(result["tcp_connections"], 2)
        self.assertEqual(result["udp_connections"], 1)
        self.assertEqual(result["network_in_bytes"], 250)
        self.assertEqual(result["network_out_bytes"], 250)
        self.assertEqual(result["failed_ssh_attempts"], 1)
        self.assertEqual(result["listening_ports"], [22, 5353])
        self.assertEqual(result["connections"][0]["remote_ip"], "203.0.113.8")
        self.assertEqual(result["connections"][0]["local_port"], 40000)
        self.assertEqual(journal.call_args.args[0][0], "journalctl")


if __name__ == "__main__":
    unittest.main()
