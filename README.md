# Common Web Vulnerabilities - Offline Classroom Lab

A ready-to-run challenge pack for Session 06 of the UCT cybersecurity workshop series. Each student runs an isolated copy on their own computer. The lab uses only Python's standard library and requires no database installation, Docker, internet connection, or third-party Python packages.

## Start the lab

### Windows

```powershell
git clone https://github.com/bsYaSSiNe/Common-Web-Vulnerabilities.git
cd Common-Web-Vulnerabilities
py -3 server.py
```

Or double-click `START_LAB.bat`.

### macOS or Linux

```bash
git clone https://github.com/bsYaSSiNe/Common-Web-Vulnerabilities.git
cd Common-Web-Vulnerabilities
python3 server.py
```

Open <http://127.0.0.1:8080>. Stop both local servers with `Ctrl+C`.

## Included challenges

| # | Challenge | Vulnerability | Suggested time |
|---|---|---|---:|
| 01 | Exposed Backup | Content discovery and security misconfiguration | 10 min |
| 02 | SQL Login | SQL injection | 12 min |
| 03 | Support Guestbook | Stored cross-site scripting | 15 min |
| 04 | Invoice Viewer | IDOR / broken object-level authorization | 12 min |
| 05 | Document Center | Path traversal | 10 min |
| 06 | Network Diagnostic | Command injection using a safe emulator | 12 min |
| 07 | Account Email | CSRF using a separate local origin | 12 min |
| 08 | Remote Preview | SSRF using a simulated internal service | 12 min |

## Lightweight tools

The application itself needs only Python. Optional classroom tools:

- Browser DevTools
- `curl`
- `ffuf`
- `dirsearch`

Bundled wordlists keep every scan small and deterministic:

```bash
ffuf -u http://127.0.0.1:8080/FUZZ -w wordlists/content.txt -mc all -fc 404
dirsearch -u http://127.0.0.1:8080 -w wordlists/content.txt --exclude-status 404
```

## Teaching material

- [Student Guide](STUDENT_GUIDE.md)
- [Instructor Runbook and Answer Key](instructor/INSTRUCTOR_GUIDE.md)
- [Troubleshooting](TROUBLESHOOTING.md)

## Design notes

- The server binds to `127.0.0.1` by default.
- Command injection and SSRF are emulated; the lab never executes operating-system commands or makes outbound network requests.
- The CSRF demonstration starts a second local origin on port `8081`.
- No Burp Suite, SQLMap, large wordlist, or active scanner is required.

## Tests

```bash
python -m unittest discover -s tests -v
```
