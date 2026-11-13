@echo off
echo ========================================================
echo Starting AI ScamShield Cybersecurity Platform...
echo Local URL: http://localhost:8000
echo ========================================================
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
pause
