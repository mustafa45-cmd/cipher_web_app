@echo off
chcp 65001 >nul
echo ========================================
echo   Kriptoloji Uygulaması - Kurulum
echo ========================================
echo.

cd /d "%~dp0"

echo Python sürümü kontrol ediliyor...
python --version
if errorlevel 1 (
    echo.
    echo HATA: Python yüklü değil!
    echo Lütfen Python'u yükleyin: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo.
echo pip güncelleniyor...
python -m pip install --upgrade pip

echo.
echo Bağımlılıklar yükleniyor...
echo.

python -m pip install -r requirements.txt

if errorlevel 1 (
    echo.
    echo HATA: Bağımlılıklar yüklenemedi!
    pause
    exit /b 1
)

echo.
echo ========================================
echo   Kurulum tamamlandı!
echo ========================================
echo.
echo BAŞLAT.bat dosyasına çift tıklayarak uygulamayı başlatabilirsiniz.
echo.
pause




