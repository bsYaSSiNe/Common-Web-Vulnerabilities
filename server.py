#!/usr/bin/env python3
"""Offline Common Web Vulnerabilities classroom lab.

The lab intentionally implements small vulnerable behaviors for localhost
teaching. It uses only Python's standard library. Potentially dangerous
operations such as command execution and outbound SSRF are safely emulated.
"""

from __future__ import annotations

import argparse
import html
import json
import posixpath
import secrets
import sqlite3
import threading
import webbrowser
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_ATTACKER_PORT = 8081

FLAGS = {
    "discovery": "flag{enumeration_finds_exposed_backups}",
    "sqli": "flag{parameterized_queries_stop_injection}",
    "xss": "flag{output_encoding_breaks_xss}",
    "idor": "flag{authorize_every_object_request}",
    "traversal": "flag{canonicalize_and_allowlist_paths}",
    "command": "flag{never_build_shell_commands_from_input}",
    "csrf": "flag{state_changes_need_csrf_protection}",
    "ssrf": "flag{servers_must_restrict_outbound_requests}",
}

SESSIONS: dict[str, dict[str, object]] = {}
SESSION_LOCK = threading.Lock()

STYLE = r"""
<style>
  :root {
    --navy:#082f5b; --blue:#0877b7; --sky:#25a9df; --gold:#c79a43;
    --copper:#b95334; --cream:#f7f0e5; --paper:#fffdf9; --ink:#192a3a;
    --muted:#61707d; --green:#16845b; --red:#b64236;
  }
  * { box-sizing:border-box; }
  body {
    margin:0; min-height:100vh; color:var(--ink); font-family:Arial,sans-serif;
    background:radial-gradient(circle at 88% 5%,#177caf66 0 10%,transparent 24%),linear-gradient(135deg,#061b32,#0a4770 58%,#073154);
  }
  header { padding:24px 6vw 20px; color:white; border-bottom:3px solid var(--gold); }
  header h1 { margin:7px 0 2px; font-size:clamp(25px,4vw,42px); }
  header p { margin:5px 0 0; color:#d8ebf5; }
  main { width:min(1060px,calc(100% - 32px)); margin:30px auto 60px; }
  nav { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:18px; }
  nav a { color:white; text-decoration:none; background:#ffffff18; border:1px solid #ffffff38; padding:8px 11px; border-radius:999px; }
  .card { background:var(--paper); border-radius:18px; padding:26px; margin:18px 0; box-shadow:0 18px 55px #0005; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(285px,1fr)); gap:16px; }
  .challenge { display:flex; flex-direction:column; min-height:250px; border-top:5px solid var(--blue); }
  .challenge .actions { margin-top:auto; }
  .tag { color:var(--gold); font-weight:800; letter-spacing:1.5px; font-size:12px; }
  .difficulty { float:right; color:var(--muted); font-size:12px; font-weight:700; }
  h2,h3 { color:var(--navy); } h2 { margin-top:7px; }
  code,pre,textarea,input { font-family:Consolas,"Courier New",monospace; }
  code { background:#eaf5fa; padding:2px 5px; border-radius:4px; }
  pre { white-space:pre-wrap; word-break:break-word; }
  button,.button { display:inline-block; border:0; background:var(--blue); color:white; padding:11px 17px; border-radius:9px; cursor:pointer; text-decoration:none; font-weight:750; }
  button:hover,.button:hover { background:var(--navy); }
  .secondary { background:var(--gold); } .danger { background:var(--copper); }
  .result { padding:17px; border-left:5px solid var(--gold); background:var(--cream); margin:14px 0; }
  .error { border-color:var(--red); background:#f8e9e4; }
  .success { border-color:var(--green); background:#e9f7ef; }
  .info { border-color:var(--sky); background:#eaf5fa; }
  label { display:block; font-weight:700; margin:12px 0 5px; }
  input,textarea,select { width:100%; border:1px solid #b9c6ce; border-radius:8px; padding:10px; background:white; }
  textarea { min-height:110px; }
  details { border:1px solid #ded4c4; border-radius:9px; padding:10px 12px; margin:8px 0; background:#fbf7ef; }
  summary { cursor:pointer; font-weight:700; color:var(--navy); }
  table { width:100%; border-collapse:collapse; }
  th,td { padding:10px; border-bottom:1px solid #dedede; text-align:left; vertical-align:top; }
  th { color:var(--navy); }
  .small { color:var(--muted); font-size:13px; }
  .method { display:grid; grid-template-columns:repeat(6,1fr); gap:6px; margin:15px 0; }
  .method span { padding:8px 5px; text-align:center; color:white; background:var(--navy); border-radius:6px; font-size:12px; font-weight:700; }
  @media (max-width:700px) { .method { grid-template-columns:repeat(2,1fr); } .card { padding:20px; } }
</style>
"""


def page(title: str, body: str) -> str:
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>{html.escape(title)} - Common Web Vulnerabilities</title>{STYLE}</head><body>
<header><div class='tag'>UCT / SESSION 06 / OFFLINE CLASSROOM LAB</div>
<h1>Common Web Vulnerabilities</h1><p>Discover. Reproduce. Prove impact. Explain the fix.</p></header>
<main><nav><a href='/'>Challenge board</a><a href='/method'>Method card</a><a href='/toolbox'>Toolbox</a><a href='/reset'>Reset session</a></nav>{body}</main></body></html>"""


def safe_json(value: object) -> str:
    return html.escape(json.dumps(value, indent=2))


def make_database() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE users (username TEXT, password TEXT, role TEXT)")
    connection.executemany(
        "INSERT INTO users VALUES (?, ?, ?)",
        [("student", "workshop", "student"), ("admin", "vault-2026", "admin")],
    )
    return connection


class LabHandler(BaseHTTPRequestHandler):
    server_version = "UCTCommonVulnsLab/1.0"

    def log_message(self, format: str, *args: object) -> None:
        return

    def request_cookies(self) -> dict[str, str]:
        jar = cookies.SimpleCookie()
        jar.load(self.headers.get("Cookie", ""))
        return {key: morsel.value for key, morsel in jar.items()}

    def session(self) -> tuple[str, dict[str, object], bool]:
        session_id = self.request_cookies().get("cwv_session", "")
        created = False
        with SESSION_LOCK:
            if not session_id or session_id not in SESSIONS:
                session_id = secrets.token_urlsafe(18)
                SESSIONS[session_id] = {
                    "email": "student@uct.local",
                    "messages": [],
                    "xss_proved": False,
                }
                created = True
            return session_id, SESSIONS[session_id], created

    def send_html(self, status: int, document: str, headers: list[tuple[str, str]] | None = None) -> None:
        session_id, _, created = self.session()
        data = document.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if created:
            self.send_header("Set-Cookie", f"cwv_session={session_id}; Path=/; HttpOnly; SameSite=Lax")
        for name, value in headers or []:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def send_text(self, status: int, text: str, content_type: str = "text/plain; charset=utf-8") -> None:
        session_id, _, created = self.session()
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if created:
            self.send_header("Set-Cookie", f"cwv_session={session_id}; Path=/; HttpOnly; SameSite=Lax")
        self.end_headers()
        self.wfile.write(data)

    def form_data(self) -> dict[str, str]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        parsed = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"), keep_blank_values=True)
        return {key: values[0] for key, values in parsed.items()}

    def route(self) -> str:
        return urlsplit(self.path).path

    def query(self) -> dict[str, str]:
        parsed = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        return {key: values[0] for key, values in parsed.items()}

    def do_GET(self) -> None:
        route = self.route()
        routes = {
            "/": self.show_board,
            "/method": self.show_method,
            "/toolbox": self.show_toolbox,
            "/reset": self.reset_session,
            "/challenge/discovery": self.show_discovery,
            "/challenge/sqli": self.show_sqli,
            "/challenge/xss": self.show_xss,
            "/challenge/idor": self.show_idor,
            "/challenge/traversal": self.show_traversal,
            "/challenge/command": self.show_command,
            "/challenge/csrf": self.show_csrf,
            "/challenge/ssrf": self.show_ssrf,
            "/backup-config/": self.show_backup,
            "/backup-config/.env.backup": self.show_backup_file,
            "/admin": self.show_admin_decoy,
            "/api": self.show_api_decoy,
            "/assets": self.show_assets_decoy,
            "/api/invoice": self.show_invoice,
            "/download": self.download_file,
            "/xss/proof": self.xss_proof,
            "/robots.txt": self.show_robots,
        }
        handler = routes.get(route)
        if handler:
            handler()
        else:
            self.send_html(404, page("Not found", "<section class='card'><h2>404</h2><p>No route matched this request.</p></section>"))

    def do_POST(self) -> None:
        route = self.route()
        routes = {
            "/login": self.process_login,
            "/guestbook": self.process_guestbook,
            "/tools/ping": self.process_ping,
            "/account/email": self.process_email_change,
            "/preview": self.process_preview,
        }
        handler = routes.get(route)
        if handler:
            handler()
        else:
            self.send_html(404, page("Not found", "<section class='card'><h2>404</h2></section>"))

    def show_board(self) -> None:
        cards = [
            ("01", "Exposed Backup", "Tool-assisted", "Use a tiny wordlist with ffuf or dirsearch, then inspect the discovered backup.", "/challenge/discovery"),
            ("02", "SQL Login", "Core", "Manipulate a login query manually and explain parameterized queries.", "/challenge/sqli"),
            ("03", "Support Guestbook", "Core", "Prove stored JavaScript execution and identify the correct output defense.", "/challenge/xss"),
            ("04", "Invoice Viewer", "Core", "Test whether changing an object identifier crosses an authorization boundary.", "/challenge/idor"),
            ("05", "Document Center", "Core", "Escape an intended virtual directory and recover a private file.", "/challenge/traversal"),
            ("06", "Network Diagnostic", "Core", "Find unsafe command construction in a safe command emulator.", "/challenge/command"),
            ("07", "Account Email", "Core", "Trigger a cross-origin state change with no anti-CSRF token.", "/challenge/csrf"),
            ("08", "Remote Preview", "Bonus", "Make the server reach a simulated internal metadata service.", "/challenge/ssrf"),
        ]
        rendered = "".join(
            f"""<article class='card challenge'><div><span class='tag'>CHALLENGE {number}</span><span class='difficulty'>{level}</span></div>
            <h2>{title}</h2><p>{description}</p><div class='actions'><a class='button' href='{path}'>Open challenge</a></div></article>"""
            for number, title, level, description, path in cards
        )
        body = f"""<section class='card'><div class='tag'>STUDENT START</div><h2>Challenge board</h2>
        <p>Establish normal behavior before using a payload or tool. Record the request, response, evidence, impact, and fix.</p>
        <div class='method'><span>BASELINE</span><span>INPUT</span><span>HYPOTHESIS</span><span>ONE TEST</span><span>PROOF</span><span>FIX</span></div></section>
        <section class='grid'>{rendered}</section>"""
        self.send_html(200, page("Challenge board", body))

    def show_method(self) -> None:
        body = """<section class='card'><div class='tag'>QUICK REFERENCE</div><h2>Vulnerability investigation card</h2>
        <table><tr><th>Step</th><th>Question</th><th>Evidence to record</th></tr>
        <tr><td>Baseline</td><td>What happens normally?</td><td>Method, endpoint, inputs, status, body, and state.</td></tr>
        <tr><td>Map input</td><td>What can the user or tool control?</td><td>Exact parameter, cookie, path, header, or object ID.</td></tr>
        <tr><td>Hypothesis</td><td>Which security assumption may be wrong?</td><td>If X is trusted, changing X may cause Y.</td></tr>
        <tr><td>One test</td><td>What smallest change tests that idea?</td><td>Exact before and after value.</td></tr>
        <tr><td>Proof</td><td>What server-side evidence demonstrates impact?</td><td>Response, persistent state, data, action, and flag.</td></tr>
        <tr><td>Fix</td><td>What control should prevent it?</td><td>Specific validation, encoding, authorization, or architecture.</td></tr></table></section>"""
        self.send_html(200, page("Method card", body))

    def show_toolbox(self) -> None:
        body = """<section class='card'><div class='tag'>LIGHTWEIGHT TOOLS</div><h2>Commands used in this lab</h2>
        <p>Run commands from the repository root so the bundled wordlists resolve correctly.</p>
        <h3>ffuf</h3><pre class='result info'>ffuf -u http://127.0.0.1:8080/FUZZ -w wordlists/content.txt -mc all -fc 404</pre>
        <h3>dirsearch</h3><pre class='result info'>dirsearch -u http://127.0.0.1:8080 -w wordlists/content.txt --exclude-status 404</pre>
        <h3>Invoice IDs with ffuf</h3><pre class='result info'>ffuf -u "http://127.0.0.1:8080/api/invoice?id=FUZZ" -w wordlists/ids.txt -mc 200</pre>
        <h3>curl baseline</h3><pre class='result info'>curl -i http://127.0.0.1:8080/robots.txt</pre>
        <p class='small'>The lab is designed so manual understanding comes before automation.</p></section>"""
        self.send_html(200, page("Toolbox", body))

    def reset_session(self) -> None:
        session_id = self.request_cookies().get("cwv_session", "")
        with SESSION_LOCK:
            SESSIONS.pop(session_id, None)
        self.send_html(200, page("Reset", "<section class='card'><h2>Session reset</h2><p>Reload the challenge board to begin from a clean state.</p><a class='button' href='/'>Continue</a></section>"), [("Set-Cookie", "cwv_session=deleted; Path=/; Max-Age=0")])

    def show_discovery(self) -> None:
        body = """<section class='card'><div class='tag'>CHALLENGE 01 / TOOL-ASSISTED</div><h2>Exposed Backup</h2>
        <p>The application team removed a sensitive backup link from navigation. Determine whether the resource is still publicly reachable.</p>
        <div class='result info'><b>Target:</b> <code>http://127.0.0.1:8080/FUZZ</code><br><b>Wordlist:</b> <code>wordlists/content.txt</code></div>
        <details><summary>Hint 1</summary><p>Use the exact ffuf or dirsearch command on the Toolbox page.</p></details>
        <details><summary>Hint 2</summary><p>Investigate unusual 200 and 403 responses manually after discovery.</p></details></section>"""
        self.send_html(200, page("Exposed Backup", body))

    def show_backup(self) -> None:
        body = """<section class='card'><div class='tag'>INDEX OF /backup-config/</div><h2>Backup directory</h2>
        <table><tr><th>Name</th><th>Modified</th></tr><tr><td><a href='/backup-config/.env.backup'>.env.backup</a></td><td>2026-08-09</td></tr></table></section>"""
        self.send_html(200, page("Backup directory", body))

    def show_backup_file(self) -> None:
        text = f"""APP_ENV=training
DATABASE_USER=workshop
METADATA_URL=http://metadata.internal/latest
TRAINING_NOTE={FLAGS['discovery']}
"""
        self.send_text(200, text)

    def show_admin_decoy(self) -> None:
        self.send_html(403, page("Forbidden", "<section class='card'><h2>403 Forbidden</h2><p>Administrator authentication required.</p></section>"))

    def show_api_decoy(self) -> None:
        self.send_text(200, json.dumps({"service": "training-api", "version": 1}), "application/json")

    def show_assets_decoy(self) -> None:
        self.send_html(200, page("Assets", "<section class='card'><h2>Static assets</h2><p>No directory listing is available.</p></section>"))

    def show_robots(self) -> None:
        self.send_text(200, "User-agent: *\nDisallow: /backup-config/\n")

    def show_sqli(self) -> None:
        body = """<section class='card'><div class='tag'>CHALLENGE 02 / SQL INJECTION</div><h2>SQL Login</h2>
        <p>Log in as the administrator without knowing the administrator password. Test manually and record the exact query assumption.</p>
        <form method='post' action='/login'><label>Username</label><input name='username' value='student'><label>Password</label><input name='password' type='password' value='wrong'><p><button type='submit'>Sign in</button></p></form>
        <details><summary>Hint 1</summary><p>Establish a failed-login baseline and inspect the submitted form fields.</p></details>
        <details><summary>Hint 2</summary><p>Consider how a quote and SQL comment could alter a concatenated WHERE clause.</p></details></section>"""
        self.send_html(200, page("SQL Login", body))

    def process_login(self) -> None:
        form = self.form_data()
        username = form.get("username", "")
        password = form.get("password", "")
        query = f"SELECT username, role FROM users WHERE username = '{username}' AND password = '{password}'"
        connection = make_database()
        try:
            row = connection.execute(query).fetchone()
        except sqlite3.Error as error:
            row = None
            error_text = str(error)
        else:
            error_text = ""
        finally:
            connection.close()
        if row and row[1] == "admin":
            result = {"success": True, "user": row[0], "role": row[1], "flag": FLAGS["sqli"]}
            body = f"<section class='card'><div class='tag'>AUTHENTICATED</div><h2>Administrator session</h2><pre class='result success'>{safe_json(result)}</pre><p><a class='button' href='/challenge/sqli'>Return</a></p></section>"
            self.send_html(200, page("Authenticated", body))
        else:
            detail = f"<p class='small'>Database message: {html.escape(error_text)}</p>" if error_text else ""
            body = f"<section class='card'><div class='tag'>BASELINE</div><h2>Login failed</h2><div class='result error'>Invalid username or password.</div>{detail}<p><a class='button' href='/challenge/sqli'>Try again</a></p></section>"
            self.send_html(401, page("Login failed", body))

    def show_xss(self) -> None:
        _, state, _ = self.session()
        messages = state.get("messages", [])
        rendered = "".join(f"<div class='result'>{message}</div>" for message in messages) or "<p class='small'>No messages yet.</p>"
        proof = f"<div class='result success'>JavaScript execution was observed.<br>Flag: <code>{FLAGS['xss']}</code></div>" if state.get("xss_proved") else ""
        body = f"""<section class='card'><div class='tag'>CHALLENGE 03 / STORED XSS</div><h2>Support Guestbook</h2>
        <p>Messages are displayed to support staff. Demonstrate JavaScript execution, then explain why input filtering alone is not the primary defense.</p>
        {proof}<form method='post' action='/guestbook'><label>Message</label><textarea name='message'>Hello support team</textarea><p><button type='submit'>Post message</button></p></form>
        <h3>Stored messages</h3>{rendered}
        <details><summary>Hint 1</summary><p>Test harmless HTML first, then compare how it is rendered.</p></details>
        <details><summary>Hint 2</summary><p>A deterministic proof payload can request <code>/xss/proof</code> from an image error handler.</p></details>
        <details><summary>Hint 3</summary><pre>&lt;img src=x onerror="fetch('/xss/proof')"&gt;</pre><p>After it executes, reload once.</p></details></section>"""
        self.send_html(200, page("Support Guestbook", body))

    def process_guestbook(self) -> None:
        _, state, _ = self.session()
        message = self.form_data().get("message", "")
        messages = state.setdefault("messages", [])
        if isinstance(messages, list):
            messages.append(message)
        self.send_html(303, "", [("Location", "/challenge/xss")])

    def xss_proof(self) -> None:
        _, state, _ = self.session()
        state["xss_proved"] = True
        self.send_text(200, "xss proof recorded")

    def show_idor(self) -> None:
        body = """<section class='card'><div class='tag'>CHALLENGE 04 / BROKEN ACCESS CONTROL</div><h2>Invoice Viewer</h2>
        <p>You are signed in as Alya. Your invoice is <a href='/api/invoice?id=1001'>invoice 1001</a>. Determine whether the server authorizes every requested object.</p>
        <div class='result info'><b>Optional ID wordlist:</b> <code>wordlists/ids.txt</code></div>
        <details><summary>Hint 1</summary><p>Capture the normal request and identify the object identifier.</p></details>
        <details><summary>Hint 2</summary><p>Change only the numeric ID or use the small ID wordlist with ffuf.</p></details></section>"""
        self.send_html(200, page("Invoice Viewer", body))

    def show_invoice(self) -> None:
        invoice_id = self.query().get("id", "")
        invoices = {
            "1001": {"owner": "alya", "item": "Student Pass", "amount": 15},
            "1002": {"owner": "instructor", "item": "Instructor Vault", "amount": 120, "flag": FLAGS["idor"]},
            "1003": {"owner": "guest", "item": "Guest Pass", "amount": 5},
        }
        invoice = invoices.get(invoice_id)
        if not invoice:
            self.send_text(404, json.dumps({"error": "invoice not found"}), "application/json")
            return
        self.send_text(200, json.dumps({"invoice_id": invoice_id, **invoice}, indent=2), "application/json")

    def show_traversal(self) -> None:
        body = """<section class='card'><div class='tag'>CHALLENGE 05 / PATH TRAVERSAL</div><h2>Document Center</h2>
        <p>The download endpoint is intended to serve files from the public document directory.</p>
        <p><a class='button' href='/download?file=welcome.txt'>Download welcome.txt</a></p>
        <div class='result info'><b>Private target clue:</b> <code>private/flag.txt</code></div>
        <details><summary>Hint 1</summary><p>Map how the <code>file</code> parameter becomes a path under <code>public/</code>.</p></details>
        <details><summary>Hint 2</summary><p>Parent-directory sequences can escape the intended folder when paths are not constrained.</p></details></section>"""
        self.send_html(200, page("Document Center", body))

    def download_file(self) -> None:
        requested = self.query().get("file", "")
        virtual_path = posixpath.normpath("/public/" + requested).lstrip("/")
        files = {
            "public/welcome.txt": "Welcome to the UCT common vulnerabilities lab.\n",
            "public/schedule.txt": "Session 06: Common Web Vulnerabilities\n",
            "private/flag.txt": FLAGS["traversal"] + "\n",
        }
        content = files.get(virtual_path)
        if content is None:
            self.send_text(404, "file not found\n")
        else:
            self.send_text(200, content)

    def show_command(self) -> None:
        body = """<section class='card'><div class='tag'>CHALLENGE 06 / COMMAND INJECTION</div><h2>Network Diagnostic</h2>
        <p>The application builds a diagnostic command from the supplied host. Determine whether another command can be appended.</p>
        <form method='post' action='/tools/ping'><label>Host</label><input name='host' value='127.0.0.1'><p><button type='submit'>Run diagnostic</button></p></form>
        <details><summary>Hint 1</summary><p>Capture the normal output and identify the controllable command fragment.</p></details>
        <details><summary>Hint 2</summary><p>Use a command separator followed by a harmless identity command.</p></details>
        <details><summary>Hint 3</summary><p>The training flag file is represented as <code>/app/flag.txt</code>.</p></details></section>"""
        self.send_html(200, page("Network Diagnostic", body))

    def process_ping(self) -> None:
        host = self.form_data().get("host", "")
        output = [f"$ ping -c 1 {host}", f"PING {host}: 1 packet transmitted, 1 received"]
        lower = host.lower()
        if ";" in host or "&&" in host or "|" in host:
            if "whoami" in lower:
                output.append("www-data")
            if "cat /app/flag.txt" in lower or "type c:\\app\\flag.txt" in lower:
                output.append(FLAGS["command"])
        body = f"<section class='card'><div class='tag'>COMMAND OUTPUT</div><h2>Diagnostic result</h2><pre class='result'>{html.escape(chr(10).join(output))}</pre><p><a class='button' href='/challenge/command'>Return</a></p></section>"
        self.send_html(200, page("Diagnostic result", body))

    def show_csrf(self) -> None:
        _, state, _ = self.session()
        email = html.escape(str(state.get("email", "student@uct.local")))
        body = f"""<section class='card'><div class='tag'>CHALLENGE 07 / CSRF</div><h2>Account Email</h2>
        <p>Current email: <code>{email}</code></p>
        <form method='post' action='/account/email'><label>New email</label><input name='email' value='student@uct.local'><p><button type='submit'>Change email</button></p></form>
        <div class='result info'><b>Attacker origin:</b> <a href='http://127.0.0.1:8081/csrf-demo'>http://127.0.0.1:8081/csrf-demo</a></div>
        <details><summary>Hint 1</summary><p>Inspect the legitimate state-changing request. Is there an unpredictable anti-CSRF token?</p></details>
        <details><summary>Hint 2</summary><p>Visit the separate attacker origin while signed in, then compare account state.</p></details></section>"""
        self.send_html(200, page("Account Email", body))

    def process_email_change(self) -> None:
        _, state, _ = self.session()
        email = self.form_data().get("email", "")
        state["email"] = email
        flag = f"<br>Flag: <code>{FLAGS['csrf']}</code>" if email == "attacker@demo.local" else ""
        body = f"<section class='card'><div class='tag'>STATE CHANGED</div><h2>Email updated</h2><div class='result success'>New email: <code>{html.escape(email)}</code>{flag}</div><p><a class='button' href='/challenge/csrf'>Return to account</a></p></section>"
        self.send_html(200, page("Email updated", body))

    def show_ssrf(self) -> None:
        body = """<section class='card'><div class='tag'>CHALLENGE 08 / SSRF BONUS</div><h2>Remote Preview</h2>
        <p>The server retrieves a remote URL and returns a preview. Determine whether it can reach a simulated internal metadata service.</p>
        <form method='post' action='/preview'><label>URL</label><input name='url' value='https://news.demo.local/article'><p><button type='submit'>Fetch preview</button></p></form>
        <details><summary>Hint 1</summary><p>Establish the normal response, then revisit evidence from Challenge 01.</p></details>
        <details><summary>Hint 2</summary><p>The exposed backup contains an internal metadata URL.</p></details></section>"""
        self.send_html(200, page("Remote Preview", body))

    def process_preview(self) -> None:
        url = self.form_data().get("url", "")
        if url == "https://news.demo.local/article":
            result = {"status": 200, "title": "Workshop News", "preview": "Session 06 is live."}
        elif url == "http://metadata.internal/latest":
            result = {"status": 200, "service": "internal-metadata", "training_secret": FLAGS["ssrf"]}
        else:
            result = {"status": 502, "error": "upstream unavailable", "requested_url": url}
        body = f"<section class='card'><div class='tag'>SERVER-SIDE FETCH RESULT</div><h2>Remote preview</h2><pre class='result'>{safe_json(result)}</pre><p><a class='button' href='/challenge/ssrf'>Return</a></p></section>"
        self.send_html(200, page("Remote preview", body))


class AttackerHandler(BaseHTTPRequestHandler):
    server_version = "UCTAttackerDemo/1.0"

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        if urlsplit(self.path).path != "/csrf-demo":
            self.send_response(404)
            self.end_headers()
            return
        document = f"""<!doctype html><html><head><meta charset='utf-8'><title>Prize page</title>{STYLE}</head><body>
        <header><div class='tag'>SEPARATE ORIGIN / PORT 8081</div><h1>Workshop Prize</h1></header><main>
        <section class='card'><h2>Loading your prize...</h2><p>This page automatically submits a cross-origin form.</p>
        <form id='attack' method='post' action='http://127.0.0.1:8080/account/email'>
        <input type='hidden' name='email' value='attacker@demo.local'></form></section>
        <script>document.getElementById('attack').submit();</script></main></body></html>"""
        data = document.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the offline Common Web Vulnerabilities lab.")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Main app port (default: 8080)")
    parser.add_argument("--attacker-port", type=int, default=DEFAULT_ATTACKER_PORT, help="CSRF demo port (default: 8081)")
    parser.add_argument("--open", action="store_true", help="Open the challenge board in the default browser")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    app_server = ThreadingHTTPServer((args.host, args.port), LabHandler)
    attacker_server = ThreadingHTTPServer((args.host, args.attacker_port), AttackerHandler)
    attacker_thread = threading.Thread(target=attacker_server.serve_forever, daemon=True)
    attacker_thread.start()
    app_url = f"http://{args.host}:{args.port}"
    attacker_url = f"http://{args.host}:{args.attacker_port}/csrf-demo"
    print("\nCommon Web Vulnerabilities classroom lab")
    print(f"Main app:      {app_url}")
    print(f"CSRF attacker: {attacker_url}")
    print("Stop both servers: press Ctrl+C in this window\n")
    if args.open:
        threading.Timer(0.5, lambda: webbrowser.open(app_url)).start()
    try:
        app_server.serve_forever()
    except KeyboardInterrupt:
        print("\nLab stopped.")
    finally:
        app_server.server_close()
        attacker_server.shutdown()
        attacker_server.server_close()
        attacker_thread.join(timeout=2)


if __name__ == "__main__":
    main()
