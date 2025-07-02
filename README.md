# 🤖 Telegram Shodan Security Bot

Bot Telegram yang terintegrasi dengan Shodan API untuk pencarian dan analisis keamanan perangkat yang terhubung ke internet dengan vulnerability assessment mendalam.

## ✨ Fitur

- 🔍 **Pencarian Shodan**: Cari perangkat/host menggunakan query Shodan
- 🖥️ **Analisis Host**: Dapatkan informasi detail tentang IP address tertentu
- 📊 **Statistik**: Hitung jumlah hasil untuk query tertentu
- 💳 **Info API**: Cek quota dan informasi API Shodan
- 🎯 **Interface Intuitif**: Keyboard inline untuk navigasi mudah
- 🛡️ **Vulnerability Analysis**: Analisis keamanan mendalam dengan database vulnerability
- 🔐 **Chat ID Whitelist**: Kontrol akses bot berdasarkan Chat ID

## 🏗️ Arsitektur

```
┌─────────────────┐                           ┌─────────────────┐
│  Telegram Bot   │◄─────────────────────────►│   Shodan API    │
│ (Security Bot)  │    Direct Integration     │                 │
└─────────────────┘                           └─────────────────┘
```

- **Telegram Bot**: Interface pengguna melalui Telegram
- **Security Analysis**: Sistem analisis keamanan dengan vulnerability database
- **Shodan API**: API eksternal untuk data perangkat internet

## 📋 Prerequisites

- Python 3.8 atau lebih baru
- Token Bot Telegram (dari @BotFather)
- API Key Shodan (dari https://account.shodan.io/)

## 🚀 Instalasi

### 1. Clone Repository

```bash
git clone <repository-url>
cd TelegramShodanBot
```

### 2. Setup Environment

```bash
# Copy file environment example
cp .env.example .env

# Edit file .env dan isi dengan token/API key Anda
notepad .env  # Windows
# atau
nano .env     # Linux/Mac
```

### 3. Isi File .env

```env
# Telegram Bot Token - dapatkan dari @BotFather di Telegram
TELEGRAM_BOT_TOKEN=your_actual_telegram_bot_token

# Shodan API Key - dapatkan dari https://account.shodan.io/
SHODAN_API_KEY=your_actual_shodan_api_key

# Admin Chat ID - Chat ID yang memiliki akses admin (untuk mengelola whitelist)
# Contoh: ADMIN_CHAT_ID=123456789
ADMIN_CHAT_ID=

# Chat ID Whitelist (Optional)
# Kosongkan untuk mengizinkan semua chat, atau isi dengan chat ID yang dipisahkan koma
# Contoh: ALLOWED_CHAT_IDS=123456789,987654321
ALLOWED_CHAT_IDS=

# Bot Configuration
# Add any additional configuration here if needed
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Jalankan Bot

```bash
# Menggunakan script launcher (recommended)
python run_bot.py

# Atau jalankan langsung
python telegram_bot.py
```

## 🎯 Cara Mendapatkan Token dan API Key

### Telegram Bot Token

1. Buka Telegram dan cari @BotFather
2. Kirim `/newbot` dan ikuti instruksi
3. Pilih nama dan username untuk bot Anda
4. Copy token yang diberikan ke file `.env`

### Shodan API Key

1. Daftar di https://account.shodan.io/
2. Login ke akun Anda
3. Pergi ke halaman API: https://account.shodan.io/
4. Copy API key Anda ke file `.env`

## 🔐 Konfigurasi Chat ID Whitelist

Bot ini mendukung fitur whitelist Chat ID untuk membatasi akses. Secara default, semua chat diizinkan menggunakan bot.

### Setup Chat ID Whitelist

1. **Dapatkan Chat ID Anda**:
   - Jalankan bot dan kirim command `/getchatid`
   - Bot akan memberikan Chat ID Anda

2. **Konfigurasi Admin dan Whitelist**:
   - Edit file `.env`
   - Set `ADMIN_CHAT_ID` dengan Chat ID admin
   - Tambahkan Chat ID ke `ALLOWED_CHAT_IDS`
   - Pisahkan multiple Chat ID dengan koma

```env
# Set admin chat ID (wajib jika menggunakan whitelist)
ADMIN_CHAT_ID=123456789

# Contoh: Mengizinkan 2 chat ID
ALLOWED_CHAT_IDS=123456789,987654321

# Kosongkan untuk mengizinkan semua chat
ALLOWED_CHAT_IDS=
```

3. **Mengelola Whitelist**:
   - Gunakan `/addchat <chat_id>` untuk menambah chat ID baru (Admin only)
   - Gunakan `/listchats` untuk melihat daftar chat ID yang diizinkan (Admin only)

### Catatan Keamanan

- Set `ADMIN_CHAT_ID` di environment variable untuk menentukan admin
- Jika `ADMIN_CHAT_ID` tidak diset, Chat ID terkecil di whitelist akan menjadi admin
- Hanya admin yang bisa menambah chat ID baru
- Jika whitelist kosong, semua chat diizinkan
- Bot akan menolak akses dari chat ID yang tidak ada di whitelist

## 📱 Penggunaan

### Perintah Dasar

- `/start` - Memulai bot dan menampilkan menu utama
- `/help` - Menampilkan bantuan lengkap
- `/search <query>` - Mencari perangkat menggunakan query Shodan
- `/host <ip>` - Mendapatkan informasi detail host
- `/count <query>` - Menghitung jumlah hasil untuk query
- `/apiinfo` - Menampilkan informasi API Shodan
- `/vulnreport <ip>` - Laporan kerentanan detail untuk IP
- `/json <ip>` - Export hasil scan ke format JSON

### Command Admin (Chat ID Whitelist)

- `/getchatid` - Mendapatkan Chat ID Anda
- `/addchat <chat_id>` - Menambah chat ID ke whitelist (Admin only)
- `/listchats` - Melihat daftar chat ID yang diizinkan (Admin only)

### Contoh Query Shodan

```bash
# Pencarian dasar
/search apache
/search nginx

# Pencarian berdasarkan port
/search port:22        # SSH servers
/search port:80        # HTTP servers
/search port:443       # HTTPS servers

# Pencarian berdasarkan lokasi
/search country:ID     # Perangkat di Indonesia
/search city:Jakarta   # Perangkat di Jakarta

# Pencarian berdasarkan organisasi
/search org:"PT Telkom"

# Pencarian vulnerability
/search vuln:CVE-2021-44228  # Log4j vulnerability

# Kombinasi query
/search apache country:ID
/search port:22 country:ID
```

### Operator Query Lanjutan

- `AND`, `OR`, `NOT` - Operator logika
- `"exact phrase"` - Pencarian exact
- `net:192.168.1.0/24` - Range network
- `before:01/01/2023` - Data sebelum tanggal
- `after:01/01/2023` - Data setelah tanggal

## 🔧 Struktur File

```
TelegramShodanBot/
├── telegram_bot.py          # Bot Telegram utama
├── telegram_bot.py          # Bot utama dengan security analysis
├── run_bot.py              # Script launcher
├── requirements.txt         # Dependencies Python
├── .env.example            # Template environment variables
├── .env                    # Environment variables (buat sendiri)
└── README.md               # Dokumentasi ini
```

## 🛠️ Pengembangan

### Menambah Fitur Baru

1. **Tambah Fitur Security Analysis Baru** di `telegram_bot.py`:
```python
@self.server.list_tools()
async def handle_list_tools() -> List[Tool]:
    return [
        # ... existing tools ...
        Tool(
            name="new_tool_name",
            description="Deskripsi tool baru",
            inputSchema={...}
        )
    ]
```

2. **Tambah Handler Bot** di `telegram_bot.py`:
```python
async def new_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Implementation
    pass

# Tambah ke setup_bot()
self.application.add_handler(CommandHandler("newcommand", self.new_command))
```

### Testing

```bash
# Test vulnerability analysis
python test_bot.py

# Test bot functionality
python run_bot.py
```

## ⚠️ Keamanan dan Etika

### Penggunaan Bertanggung Jawab

- ✅ Gunakan untuk research dan security assessment yang sah
- ✅ Hormati terms of service Shodan
- ✅ Jangan melakukan scanning yang tidak sah
- ❌ Jangan gunakan untuk aktivitas ilegal
- ❌ Jangan abuse API quota

### Keamanan Token

- Jangan commit file `.env` ke repository
- Gunakan environment variables di production
- Rotate token secara berkala
- Monitor penggunaan API

## 🐛 Troubleshooting

### Bot Tidak Merespons

1. Cek token bot di file `.env`
2. Pastikan bot sudah di-start dengan @BotFather
3. Cek koneksi internet
4. Lihat log error di terminal

### Error Shodan API

1. Cek API key di file `.env`
2. Pastikan masih ada quota API
3. Cek status Shodan API: https://status.shodan.io/

### Error Bot

1. Pastikan dependencies terinstall
2. Cek format JSON request/response
3. Lihat log error di terminal

### Error Dependencies

```bash
# Update pip
python -m pip install --upgrade pip

# Install ulang requirements
pip install -r requirements.txt --force-reinstall
```

## 📊 Monitoring

### Log Files

Bot akan menampilkan log di terminal dengan format:
```
2024-01-01 12:00:00 - telegram_bot - INFO - Bot started
2024-01-01 12:00:01 - telegram_bot - INFO - Shodan Security Bot dimulai...
```

### Metrics

- Jumlah query per hari
- Response time rata-rata
- Error rate
- API quota usage

## 🤝 Contributing

1. Fork repository
2. Buat feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push ke branch (`git push origin feature/AmazingFeature`)
5. Buat Pull Request

## 📄 License

Project ini menggunakan MIT License. Lihat file `LICENSE` untuk detail.

## 🙏 Acknowledgments

- [Shodan](https://www.shodan.io/) - Internet-connected device search engine
- [python-telegram-bot](https://github.com/python-telegram-bot/python-telegram-bot) - Telegram Bot API wrapper
- [Model Context Protocol](https://modelcontextprotocol.io/) - Protocol untuk AI tool integration

## 📞 Support

Jika Anda mengalami masalah atau memiliki pertanyaan:

1. Cek dokumentasi ini
2. Lihat [Issues](../../issues) yang sudah ada
3. Buat [Issue baru](../../issues/new) jika diperlukan

---

**⚠️ Disclaimer**: Tool ini dibuat untuk tujuan edukasi dan research. Pengguna bertanggung jawab penuh atas penggunaan tool ini. Pastikan mematuhi hukum dan regulasi yang berlaku.