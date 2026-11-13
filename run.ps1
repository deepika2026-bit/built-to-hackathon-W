Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Starting AI ScamShield Cybersecurity Platform..." -ForegroundColor Green
Write-Host "Local URL: http://localhost:8000" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Cyan
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
