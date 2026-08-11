# Troubleshooting

## Python is not recognized

Install Python 3 and enable the installer option that adds Python to PATH. Then open a new terminal.

Windows alternatives:

```powershell
py -3 server.py
python server.py
```

macOS or Linux:

```bash
python3 server.py
```

## Port 8080 or 8081 is already in use

Choose two unused ports:

```powershell
py -3 server.py --port 8090 --attacker-port 8091
```

The CSRF demonstration uses the default ports in its generated links. For the classroom, close the conflicting application and use 8080 and 8081 whenever possible.

## Stop the lab

Return to the terminal where the lab is running and press `Ctrl+C`. This stops both the main application and the CSRF demonstration server.

## ffuf or dirsearch is unavailable

The server does not require either tool. Students may inspect `robots.txt` or manually request candidates from `wordlists/content.txt`. Tool installation is optional and should be completed before class.

## Reset challenge state

Open <http://127.0.0.1:8080/reset> or clear the `cwv_session` cookie.
