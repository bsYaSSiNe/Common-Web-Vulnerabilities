# Student Guide

## Before beginning

Start the lab and open <http://127.0.0.1:8080>. Keep DevTools open. Run terminal commands from the repository root so the supplied wordlists resolve correctly.

## Evidence log

Complete this for every challenge:

```text
Challenge:
Normal request and response:
User-controlled input:
Security decision:
Hypothesis:
Single test:
Modified response:
Server-side proof:
Impact:
Recommended fix:
Flag:
```

## Lightweight tool commands

Content discovery with ffuf:

```bash
ffuf -u http://127.0.0.1:8080/FUZZ -w wordlists/content.txt -mc all -fc 404
```

Content discovery with dirsearch:

```bash
dirsearch -u http://127.0.0.1:8080 -w wordlists/content.txt --exclude-status 404
```

Invoice IDs with ffuf:

```bash
ffuf -u "http://127.0.0.1:8080/api/invoice?id=FUZZ" -w wordlists/ids.txt -mc 200
```

Basic request inspection with curl:

```bash
curl -i http://127.0.0.1:8080/robots.txt
```

## What each tool contributes

- DevTools shows the exact request, response, payload, cookie, status, and browser behavior.
- `curl` provides a clean terminal view of a single HTTP exchange.
- `ffuf` replaces `FUZZ` with every entry in a wordlist and compares responses.
- `dirsearch` discovers content paths from a wordlist and groups the results by status.

Tools identify candidates. They do not prove the vulnerability or explain its impact. Open interesting responses, establish a baseline, change one input, and collect evidence.

## Stopping the lab

Return to the terminal and press `Ctrl+C`. The main server on port 8080 and CSRF demonstration server on port 8081 stop together.
