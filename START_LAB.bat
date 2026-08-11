@echo off
setlocal
title Common Web Vulnerabilities - Local Lab
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 server.py --open
) else (
  python server.py --open
)
if not %errorlevel%==0 (
  echo.
  echo The lab could not start. Confirm Python 3 is installed.
  echo See TROUBLESHOOTING.md for help.
  pause
)
