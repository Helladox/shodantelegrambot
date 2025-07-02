@echo off
echo ========================================
echo    Telegram Shodan Bot Launcher
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python tidak ditemukan!
    echo Silakan install Python 3.8+ dari https://python.org
    pause
    exit /b 1
)

REM Check if .env file exists
if not exist ".env" (
    echo WARNING: File .env tidak ditemukan!
    echo.
    if exist ".env.example" (
        echo Silakan copy .env.example ke .env dan isi dengan token/API key Anda:
        echo copy .env.example .env
        echo.
        echo Anda perlu mengisi:
        echo - TELEGRAM_BOT_TOKEN: Dapatkan dari @BotFather di Telegram
        echo - SHODAN_API_KEY: Dapatkan dari https://account.shodan.io/
    ) else (
        echo File .env.example juga tidak ditemukan!
    )
    echo.
    pause
    exit /b 1
)

REM Install requirements if needed
echo Mengecek dependencies...
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo ERROR: Gagal menginstall dependencies!
    pause
    exit /b 1
)

echo Dependencies OK!
echo.
echo Memulai bot...
echo Bot akan berjalan hingga Anda menekan Ctrl+C
echo ========================================
echo.

REM Run the bot
python run_bot.py

echo.
echo ========================================
echo Bot telah dihentikan.
echo Terima kasih telah menggunakan Telegram Shodan Bot!
echo ========================================
pause