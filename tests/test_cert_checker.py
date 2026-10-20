import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cert_checker as cc  # noqa: E402


class ClassifyTests(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(cc.classify(31, 30, 7), cc.OK)
        self.assertEqual(cc.classify(30, 30, 7), cc.WARNING)
        self.assertEqual(cc.classify(8, 30, 7), cc.WARNING)
        self.assertEqual(cc.classify(7, 30, 7), cc.CRITICAL)
        self.assertEqual(cc.classify(0, 30, 7), cc.CRITICAL)

    def test_expired_is_failed(self):
        self.assertEqual(cc.classify(-3, 30, 7, expired=True), cc.FAILED)


class ConfigTests(unittest.TestCase):
    def test_full_example(self):
        cfg = cc.parse_config("""
# comment
warn_days: 45
critical_days: 10
timeout: 5
hosts:
  - github.com
  - example.com:8443   # inline comment
  - host: internal.lan
    port: 9443
    verify: false
  - "quoted.example"
""")
        self.assertEqual((cfg.warn_days, cfg.critical_days, cfg.timeout), (45, 10, 5.0))
        self.assertEqual([(h.host, h.port, h.verify) for h in cfg.hosts], [
            ("github.com", 443, True),
            ("example.com", 8443, True),
            ("internal.lan", 9443, False),
            ("quoted.example", 443, True),
        ])

    def test_errors(self):
        bad = {
            "no hosts": "warn_days: 30\n",
            "unknown setting": "foo: 1\nhosts:\n  - a.com\n",
            "unknown option": "hosts:\n  - host: a.com\n    colour: red\n",
            "item outside hosts": "- a.com\n",
            "bad port": "hosts:\n  - host: a.com\n    port: 99999\n",
            "thresholds": "warn_days: 5\ncritical_days: 9\nhosts:\n  - a.com\n",
            "bad verify": "hosts:\n  - host: a.com\n    verify: maybe\n",
        }
        for label, text in bad.items():
            with self.subTest(label), self.assertRaises(cc.ConfigError):
                cc.parse_config(text)

    def test_repo_configs_parse(self):
        root = Path(__file__).resolve().parent.parent
        for rel in ("domains.yml", "demo/domains.demo.yml"):
            with self.subTest(rel):
                self.assertTrue(cc.load_config(root / rel).hosts)


class ReportTests(unittest.TestCase):
    def _results(self):
        return [
            cc.Result("a.com", 443, cc.OK, 90, "2027-01-01 00:00:00 UTC", "CA", ["a.com"]),
            cc.Result("b.com", 443, cc.WARNING, 20, "2026-11-02 00:00:00 UTC", "CA", ["b.com"]),
            cc.Result("c.com", 443, cc.CRITICAL, 3, "2026-10-16 00:00:00 UTC", "CA", ["c.com"]),
            cc.Result("d.com", 443, cc.FAILED, None, error="handshake failure: refused"),
        ]

    def test_overall_and_sorting(self):
        res = self._results()
        self.assertEqual(cc.overall_status(res), cc.FAILED)
        self.assertEqual([r.host for r in cc.sorted_results(res)], ["d.com", "c.com", "b.com", "a.com"])
        self.assertEqual(cc.overall_status(res[:2]), cc.WARNING)
        self.assertEqual(cc.overall_status([]), cc.OK)

    def test_markdown_contains_table_and_details(self):
        md = cc.render_markdown(self._results(), 30, 7,
                                datetime(2026, 10, 13, 6, 0, tzinfo=timezone.utc))
        self.assertIn("| Host | Days left | Status |", md)
        self.assertIn("`c.com:443` | 3 | 🔴 critical", md)
        self.assertIn("handshake failure: refused", md)
        self.assertIn("1 failed, 1 critical, 1 warning, 1 ok", md)


@unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
class EndToEndTests(unittest.TestCase):
    """Real TLS handshakes against throw-away servers on localhost."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.certs = Path(cls.tmp.name)
        cls.servers = []

    @classmethod
    def tearDownClass(cls):
        for sock in cls.servers:
            sock.close()
        cls.tmp.cleanup()

    def _serve(self, days: int) -> int:
        crt, key = self.certs / f"{days}.crt", self.certs / f"{days}.key"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
             "-out", str(crt), "-days", str(days), "-subj", "/CN=localhost/O=Test",
             "-addext", "subjectAltName=DNS:localhost,DNS:test.local"],
            check=True, capture_output=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        self.servers.append(srv)

        def loop():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                try:
                    ctx.wrap_socket(conn, server_side=True).close()
                except (OSError, ssl.SSLError):
                    conn.close()

        threading.Thread(target=loop, daemon=True).start()
        return srv.getsockname()[1]

    def test_statuses_and_metadata(self):
        for days, expected in ((90, cc.OK), (20, cc.WARNING), (3, cc.CRITICAL)):
            with self.subTest(days=days):
                port = self._serve(days)
                r = cc.check_host(cc.HostSpec("localhost", port, verify=False), retries=0)
                self.assertEqual(r.status, expected)
                self.assertIn(r.days_left, (days - 1, days))
                self.assertIn("localhost", r.sans)
                self.assertIn("test.local", r.sans)
                self.assertIn("Test", r.issuer)

    def test_expired_by_clock_shift(self):
        port = self._serve(10)
        future = datetime.now(timezone.utc) + timedelta(days=15)
        r = cc.check_host(cc.HostSpec("localhost", port, verify=False), retries=0, now=future)
        self.assertEqual(r.status, cc.FAILED)
        self.assertLess(r.days_left, 0)
        self.assertIn("expired", r.error)

    def test_self_signed_fails_trust_check_when_verify_on(self):
        port = self._serve(90)
        r = cc.check_host(cc.HostSpec("localhost", port, verify=True), retries=0)
        self.assertEqual(r.status, cc.FAILED)
        self.assertIn("trust check failed", r.error)

    def test_handshake_failure(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()  # nothing listens here any more
        r = cc.check_host(cc.HostSpec("127.0.0.1", port, verify=False), timeout=2, retries=0)
        self.assertEqual(r.status, cc.FAILED)
        self.assertIn("handshake failure", r.error)

    def test_cli_exit_codes_and_reports(self):
        ok_port = self._serve(90)
        crit_port = self._serve(3)
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "domains.yml"
            cfg.write_text(f"hosts:\n  - host: localhost\n    port: {ok_port}\n    verify: false\n")
            self.assertEqual(cc.main(["--config", str(cfg), "--out", d, "--retries", "0"]), 0)
            self.assertTrue((Path(d) / "report.json").exists())
            self.assertTrue((Path(d) / "report.md").exists())

            cfg.write_text(f"hosts:\n  - host: localhost\n    port: {crit_port}\n    verify: false\n")
            self.assertEqual(cc.main(["--config", str(cfg), "--out", d, "--retries", "0"]), 1)

            self.assertEqual(cc.main(["--config", str(Path(d) / "missing.yml")]), 2)


if __name__ == "__main__":
    unittest.main()
