#!/usr/bin/env python3
"""
Script test untuk Telegram Shodan Bot
Menguji koneksi dan fungsi dasar tanpa menjalankan bot secara penuh
"""

import os
import sys
import asyncio
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_environment():
    """Test environment variables"""
    print("🧪 Testing Environment Variables...")
    
    telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')
    shodan_key = os.getenv('SHODAN_API_KEY')
    
    if not telegram_token or telegram_token == 'your_telegram_bot_token_here':
        print("❌ TELEGRAM_BOT_TOKEN tidak valid")
        return False
    else:
        print(f"✅ TELEGRAM_BOT_TOKEN: {telegram_token[:10]}...")
    
    if not shodan_key or shodan_key == 'your_shodan_api_key_here':
        print("❌ SHODAN_API_KEY tidak valid")
        return False
    else:
        print(f"✅ SHODAN_API_KEY: {shodan_key[:10]}...")
    
    return True

def test_dependencies():
    """Test required dependencies"""
    print("\n📦 Testing Dependencies...")
    
    required_modules = [
        'telegram',
        'shodan',
        'dotenv',
        'asyncio',
        'json'
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
            print(f"✅ {module}")
        except ImportError:
            print(f"❌ {module} - MISSING")
            missing_modules.append(module)
    
    if missing_modules:
        print(f"\n❌ Missing modules: {', '.join(missing_modules)}")
        print("💡 Run: pip install -r requirements.txt")
        return False
    
    return True

async def test_shodan_connection():
    """Test Shodan API connection"""
    print("\n🌐 Testing Shodan API Connection...")
    
    try:
        import shodan
        
        api_key = os.getenv('SHODAN_API_KEY')
        if not api_key:
            print("❌ SHODAN_API_KEY tidak ditemukan")
            return False
        
        api = shodan.Shodan(api_key)
        
        # Test API info
        info = api.info()
        print(f"✅ Shodan API connected")
        print(f"   Plan: {info.get('plan', 'N/A')}")
        print(f"   Query credits: {info.get('query_credits', 'N/A')}")
        
        return True
        
    except shodan.APIError as e:
        print(f"❌ Shodan API Error: {e}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

async def test_telegram_token():
    """Test Telegram bot token"""
    print("\n🤖 Testing Telegram Bot Token...")
    
    try:
        from telegram import Bot
        
        token = os.getenv('TELEGRAM_BOT_TOKEN')
        if not token:
            print("❌ TELEGRAM_BOT_TOKEN tidak ditemukan")
            return False
        
        bot = Bot(token=token)
        
        # Test get me
        me = await bot.get_me()
        print(f"✅ Telegram bot connected")
        print(f"   Bot name: {me.first_name}")
        print(f"   Username: @{me.username}")
        
        return True
        
    except Exception as e:
        print(f"❌ Telegram Error: {e}")
        return False

async def test_vulnerability_analysis():
    """Test vulnerability analysis functionality"""
    print("\n🛡️ Testing Vulnerability Analysis...")
    
    try:
        from telegram_bot import ShodanTelegramBot
        
        # Create bot instance
        bot = ShodanTelegramBot()
        print("✅ Bot instance created")
        
        # Test vulnerability database
        vuln_db = bot.vulnerability_db
        print(f"✅ Vulnerability database loaded: {len(vuln_db)} services")
        
        for service in vuln_db.keys():
            print(f"   - {service.upper()}: {vuln_db[service]['description']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Vulnerability Analysis Error: {e}")
        return False

def test_file_structure():
    """Test required files exist"""
    print("\n📁 Testing File Structure...")
    
    required_files = [
        'telegram_bot.py',
        'requirements.txt',
        '.env',
        'README.md'
    ]
    
    missing_files = []
    
    for file in required_files:
        if Path(file).exists():
            print(f"✅ {file}")
        else:
            print(f"❌ {file} - MISSING")
            missing_files.append(file)
    
    if missing_files:
        print(f"\n❌ Missing files: {', '.join(missing_files)}")
        return False
    
    return True

async def main():
    """Main test function"""
    print("🧪 Telegram Shodan Bot - Test Suite")
    print("=" * 50)
    
    tests = [
        ("File Structure", test_file_structure),
        ("Environment Variables", test_environment),
        ("Dependencies", test_dependencies),
        ("Shodan API", test_shodan_connection),
        ("Telegram Bot", test_telegram_token),
        ("Vulnerability Analysis", test_vulnerability_analysis)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            if asyncio.iscoroutinefunction(test_func):
                result = await test_func()
            else:
                result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Results Summary:")
    print("=" * 50)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
        if result:
            passed += 1
    
    print(f"\n📈 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Bot is ready to run.")
        print("💡 Run: python run_bot.py")
        return True
    else:
        print("⚠️  Some tests failed. Please fix the issues before running the bot.")
        return False

if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n👋 Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test suite error: {e}")
        sys.exit(1)