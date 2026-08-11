# Instructor Runbook and Answer Key

## Recommended two-hour session

| Time | Activity |
|---|---|
| 0-10 min | Vulnerability model: input, sink, missing control, impact, fix |
| 10-20 min | Challenge 01 and ffuf/dirsearch demonstration |
| 20-32 min | Challenge 02: SQL injection |
| 32-47 min | Challenge 03: stored XSS |
| 47-59 min | Challenge 04: IDOR |
| 59-67 min | Break |
| 67-77 min | Challenge 05: path traversal |
| 77-89 min | Challenge 06: command injection |
| 89-101 min | Challenge 07: CSRF |
| 101-113 min | Challenge 08: SSRF bonus or guided demonstration |
| 113-120 min | Debrief and exit ticket |

For a shorter core block, use Challenges 01-05 and assign 06-08 as demonstrations or homework.

## Vulnerability explanation formula

For every topic, explain five elements:

1. **Input:** What can the user influence?
2. **Sink or decision:** Where is that value used?
3. **Missing control:** Which validation, encoding, authorization, token, or boundary is absent?
4. **Impact:** What becomes possible?
5. **Fix:** What exact server-side control prevents it?

## Challenge 01 - Exposed Backup

**Path:** `/challenge/discovery`

**Tool commands:**

```bash
ffuf -u http://127.0.0.1:8080/FUZZ -w wordlists/content.txt -mc all -fc 404
dirsearch -u http://127.0.0.1:8080 -w wordlists/content.txt --exclude-status 404
```

**Solution:** Discover `/backup-config/`, open `.env.backup`, and recover the flag.

**Flag:** `flag{enumeration_finds_exposed_backups}`

**Impact:** Backup files can expose credentials, internal service names, secrets, and architecture details.

**Fix:** Remove backups from the web root, deny access at the server, exclude secrets from artifacts, and scan deployment packages.

**Teaching note:** Compare `200`, `403`, and `404`. The tool discovers candidates; manual inspection determines significance.

## Challenge 02 - SQL Login

**Path:** `/challenge/sqli`

**Baseline:** Normal invalid credentials return `401`.

**Example solution:** Submit `admin' --` as the username and any password. The SQL comment removes the password condition.

**Flag:** `flag{parameterized_queries_stop_injection}`

**Impact:** Authentication bypass and potentially unauthorized database access.

**Fix:** Use parameterized queries, least-privileged database accounts, generic errors, and appropriate input constraints.

**Explain:** SQL injection happens when data becomes executable query syntax. Escaping by hand and blacklisting quotes are fragile; query parameters keep code and data separate.

## Challenge 03 - Support Guestbook

**Path:** `/challenge/xss`

**Baseline:** A normal message is stored and rendered.

**Proof payload:**

```html
<img src=x onerror="fetch('/xss/proof')">
```

Reload once after execution.

**Flag:** `flag{output_encoding_breaks_xss}`

**Impact:** JavaScript executes in another user's application origin and may perform actions or read data available to that page.

**Fix:** Context-aware output encoding, safe DOM APIs, HTML sanitization only where HTML is intentionally allowed, and CSP as defense in depth.

**Explain:** The primary mistake is rendering untrusted data as active HTML. Input filtering alone cannot understand every output context.

## Challenge 04 - Invoice Viewer

**Path:** `/challenge/idor`

**Baseline:** Alya may access invoice `1001`.

**Manual solution:** Change `id=1001` to `id=1002`.

**Optional ffuf:**

```bash
ffuf -u "http://127.0.0.1:8080/api/invoice?id=FUZZ" -w wordlists/ids.txt -mc 200
```

**Flag:** `flag{authorize_every_object_request}`

**Impact:** A user reads another user's invoice.

**Fix:** Check object ownership or permission on every request. Unpredictable IDs may reduce guessing but do not replace authorization.

## Challenge 05 - Document Center

**Path:** `/challenge/traversal`

**Baseline:** `/download?file=welcome.txt` returns a public file.

**Solution:** Request `/download?file=../private/flag.txt`.

**Flag:** `flag{canonicalize_and_allowlist_paths}`

**Impact:** Reading files outside the intended directory, potentially including configuration, keys, source, or credentials.

**Fix:** Map stable identifiers to approved files, canonicalize paths, enforce an allowlisted root, and run with minimal filesystem permissions.

## Challenge 06 - Network Diagnostic

**Path:** `/challenge/command`

**Baseline:** `127.0.0.1` produces simulated ping output.

**Progression:**

```text
127.0.0.1; whoami
127.0.0.1; cat /app/flag.txt
```

**Flag:** `flag{never_build_shell_commands_from_input}`

**Impact:** In a real vulnerable application, operating-system command execution with the web process's privileges.

**Fix:** Avoid invoking a shell, use a safe library API, pass fixed argument arrays, strictly allowlist values, and isolate the process.

**Implementation note:** This lab safely emulates command output and never invokes the operating-system shell.

## Challenge 07 - Account Email

**Victim path:** `/challenge/csrf`

**Attacker origin:** `http://127.0.0.1:8081/csrf-demo`

**Solution:** Establish the legitimate email-change request, note the missing unpredictable token, then visit the attacker origin while the victim session exists. The cross-origin form changes the email to `attacker@demo.local`.

**Flag:** `flag{state_changes_need_csrf_protection}`

**Impact:** An attacker causes a signed-in user's browser to perform an unwanted state-changing action.

**Fix:** Synchronizer CSRF tokens or equivalent framework protection, SameSite cookies as defense in depth, Origin/Referer validation where appropriate, and no state changes through GET.

**Explain:** CSRF abuses the browser's automatic credential handling. It does not require the attacker to read the protected response.

## Challenge 08 - Remote Preview

**Path:** `/challenge/ssrf`

**Baseline URL:** `https://news.demo.local/article`

**Internal URL:** The exposed backup reveals `http://metadata.internal/latest`.

**Flag:** `flag{servers_must_restrict_outbound_requests}`

**Impact:** The application server can be induced to access internal services unavailable to the user.

**Fix:** Allowlist destinations, resolve and validate IP addresses, block private/link-local ranges, restrict protocols and redirects, and enforce outbound network policy.

**Implementation note:** The lab uses a virtual response map and makes no outbound network request.

## Debrief prompts

1. What was the user-controlled input?
2. Where did it reach a sensitive sink or decision?
3. Which control was missing?
4. What evidence proved impact rather than merely suspicious behavior?
5. What is the concrete server-side fix?
6. Which tasks benefited from a tool, and which still required manual reasoning?

## Exit ticket

- Name one vulnerability where validation is central.
- Name one vulnerability where output encoding is central.
- Name one vulnerability where authorization is central.
- Explain why discovering an endpoint does not prove it is vulnerable.
