#!/usr/bin/env python3
"""
Script untuk menjalankan Telegram Shodan Bot
Script ini akan memastikan semua dependencies terpasang dan menjalankan bot
"""

import os
import sys
import subprocess
import asyncio
from pathlib import Path

def check_python_version():
    """Cek versi Python"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 atau lebih baru diperlukan")
        sys.exit(1)
    print(f"✅ Python {sys.version.split()[0]} terdeteksi")

def install_requirements():
    """Install requirements jika belum ada"""
    requirements_file = Path("requirements.txt")
    if not requirements_file.exists():
        print("❌ File requirements.txt tidak ditemukan")
        sys.exit(1)
    
    print("📦 Menginstall dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies berhasil diinstall")
    except subprocess.CalledProcessError:
        print("❌ Gagal menginstall dependencies")
        sys.exit(1)

def check_env_file():
    """Cek file environment"""
    env_file = Path(".env")
    env_example = Path(".env.example")
    
    if not env_file.exists():
        if env_example.exists():
            print("⚠️  File .env tidak ditemukan")
            print("📋 Silakan copy .env.example ke .env dan isi dengan token/API key Anda:")
            print("   cp .env.example .env")
            print("\n📝 Anda perlu mengisi:")
            print("   - TELEGRAM_BOT_TOKEN: Dapatkan dari @BotFather di Telegram")
            print("   - SHODAN_API_KEY: Dapatkan dari https://account.shodan.io/")
        else:
            print("❌ File .env dan .env.example tidak ditemukan")
        sys.exit(1)
    
    # Cek isi file .env
    with open(env_file, 'r') as f:
        env_content = f.read()
    
    if "your_telegram_bot_token_here" in env_content or "your_shodan_api_key_here" in env_content:
        print("⚠️  File .env masih berisi placeholder")
        print("📝 Silakan edit file .env dan isi dengan token/API key yang valid")
        sys.exit(1)
    
    print("✅ File .env ditemukan dan terisi")

def main():
    """Main function"""
    print("🤖 Telegram Shodan Bot Launcher")
    print("=" * 40)
    
    # Cek Python version
    check_python_version()
    
    # Install requirements
    install_requirements()
    
    # Cek environment file
    check_env_file()
    
    print("\n🚀 Memulai bot...")
    print("📱 Bot akan berjalan hingga Anda menekan Ctrl+C")
    print("=" * 40)
    
    try:
        # Import dan jalankan bot
        from telegram_bot import main as bot_main
        asyncio.run(bot_main())
    except KeyboardInterrupt:
        print("\n\n👋 Bot dihentikan oleh user")
    except ImportError as e:
        print(f"❌ Error import: {e}")
        print("💡 Pastikan semua dependencies sudah terinstall")
    except Exception as e:
        print(f"❌ Error menjalankan bot: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()