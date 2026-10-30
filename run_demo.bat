@echo off
cd /d "%~dp0"
for /f "usebackq tokens=1,* delims==" %%a in ("config.env") do if "%%a"=="GROQ_API_KEY" set "GROQ_API_KEY=%%b"
start "AdaptShield server" cmd /k python server.py
echo Waiting for the models to load...
timeout /t 30 /nobreak
start "AdaptShield tunnel" cmd /k .\cloudflared.exe tunnel --url http://127.0.0.1:8000
