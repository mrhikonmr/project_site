@echo off
cd /d "%~dp0"
if not exist .venv ( py -m venv .venv )
call .venv\Scripts\activate.bat
python -m pip install -r requirements.txt
python -m flask --app app init
echo.
echo === Zapishite parol admin vyshe (pokazyvaetsya odin raz) ===
echo === Sait: http://127.0.0.1:5000 ===
set INSECURE_DEV=1
python app.py
pause
