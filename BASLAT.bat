@echo off
chcp 65001 >nul 2>&1
cls
echo ========================================
echo   Kriptoloji Uygulamasi Baslatiliyor
echo ========================================
echo.

cd /d "%~dp0"

echo [1/3] TCP Server baslatiliyor...
start "TCP Server" cmd /k "python server.py"

timeout /t 2 /nobreak >nul

echo [2/3] Flask API baslatiliyor...
start "Flask API" cmd /k "python client_api.py"

timeout /t 3 /nobreak >nul

echo [3/3] Baslatildi!
echo.
echo ========================================
echo   Basarili! Tarayicida acin:
echo   http://127.0.0.1:5001
echo ========================================
echo.
echo Servisleri durdurmak icin acilan pencereyi kapatin.
echo.
pause


