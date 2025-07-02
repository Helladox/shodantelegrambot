#!/usr/bin/env python3
"""
Telegram Bot untuk Shodan Security Analysis
Bot ini menyediakan analisis keamanan mendalam dengan vulnerability assessment
"""

import asyncio
import json
import logging
import os
from typing import Dict, Any, Optional, List
import shodan

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters
)
from telegram.constants import ParseMode
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

class ShodanTelegramBot:
    def __init__(self):
        self.bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
        if not self.bot_token:
            raise ValueError("TELEGRAM_BOT_TOKEN tidak ditemukan di environment variables")
        
        # Verify Shodan API key exists
        shodan_api_key = os.getenv('SHODAN_API_KEY')
        if not shodan_api_key:
            raise ValueError("SHODAN_API_KEY tidak ditemukan di environment variables")
        
        self.application = None
        self.shodan_api = shodan.Shodan(shodan_api_key)
        
        # Setup admin chat ID
        admin_chat_id_str = os.getenv('ADMIN_CHAT_ID', '')
        if admin_chat_id_str.strip():
            try:
                self.admin_chat_id = int(admin_chat_id_str.strip())
            except ValueError:
                logger.error("Invalid ADMIN_CHAT_ID format. Using first allowed chat ID as admin.")
                self.admin_chat_id = None
        else:
            self.admin_chat_id = None
        
        # Setup allowed chat IDs
        allowed_chat_ids_str = os.getenv('ALLOWED_CHAT_IDS', '')
        if allowed_chat_ids_str.strip():
            self.allowed_chat_ids = set(int(chat_id.strip()) for chat_id in allowed_chat_ids_str.split(',') if chat_id.strip())
        else:
            self.allowed_chat_ids = None  # None means all chats are allowed
        
        # Vulnerability database dengan remediasi
        self.vulnerability_db = {
            'ssh': {
                'port': 22,
                'description': 'SSH service detected',
                'risks': ['Brute force attacks', 'Weak credentials', 'Outdated SSH versions'],
                'remediation': [
                    'Use strong passwords or key-based authentication',
                    'Disable root login',
                    'Change default SSH port',
                    'Enable fail2ban or similar intrusion prevention',
                    'Keep SSH version updated'
                ],
                'references': [
                    'https://www.ssh.com/academy/ssh/security',
                    'https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=ssh'
                ]
            },
            'telnet': {
                'port': 23,
                'description': 'Telnet service detected',
                'risks': ['Unencrypted communication', 'Easy credential interception', 'No authentication'],
                'remediation': [
                    'Replace Telnet with SSH',
                    'Disable Telnet service completely',
                    'Use VPN for remote access',
                    'Implement network segmentation'
                ],
                'references': [
                    'https://www.cisa.gov/news-events/alerts/2011/04/27/telnet-usage-discouraged',
                    'https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=telnet'
                ]
            },
            'ftp': {
                'port': 21,
                'description': 'FTP service detected',
                'risks': ['Unencrypted data transfer', 'Anonymous access', 'Credential interception'],
                'remediation': [
                    'Use SFTP or FTPS instead',
                    'Disable anonymous FTP access',
                    'Implement strong authentication',
                    'Use secure file transfer protocols'
                ],
                'references': [
                    'https://www.cisa.gov/news-events/alerts/2000/05/12/anonymous-ftp-security',
                    'https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=ftp'
                ]
            },
            'http': {
                'port': 80,
                'description': 'HTTP service detected',
                'risks': ['Unencrypted web traffic', 'Man-in-the-middle attacks', 'Data interception'],
                'remediation': [
                    'Implement HTTPS with valid SSL certificates',
                    'Redirect HTTP to HTTPS',
                    'Use HSTS headers',
                    'Keep web server updated'
                ],
                'references': [
                    'https://www.cisa.gov/news-events/alerts/2015/06/18/transport-layer-security-best-practices',
                    'https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=http'
                ]
            },
            'rdp': {
                'port': 3389,
                'description': 'RDP service detected',
                'risks': ['Brute force attacks', 'BlueKeep vulnerability', 'Unauthorized remote access'],
                'remediation': [
                    'Enable Network Level Authentication',
                    'Use VPN for RDP access',
                    'Change default RDP port',
                    'Implement account lockout policies',
                    'Keep Windows updated'
                ],
                'references': [
                    'https://www.cisa.gov/news-events/alerts/2019/05/14/microsoft-releases-security-advisory-rdp-vulnerability-cve-2019-0708',
                    'https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=rdp'
                ]
            }
        }
        
    def analyze_vulnerabilities(self, host_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze host data for vulnerabilities and provide remediation"""
        vulnerabilities = []
        
        # Check open ports for known vulnerabilities
        if 'data' in host_data:
            for service in host_data['data']:
                port = service.get('port', 0)
                product = service.get('product', '').lower()
                
                # Check against vulnerability database
                for vuln_name, vuln_info in self.vulnerability_db.items():
                    if (port == vuln_info['port'] or 
                        vuln_name in product or 
                        vuln_name in service.get('_shodan', {}).get('module', '').lower()):
                        
                        vulnerability = {
                            'service': vuln_name.upper(),
                            'port': port,
                            'description': vuln_info['description'],
                            'risks': vuln_info['risks'],
                            'remediation': vuln_info['remediation'],
                            'references': vuln_info['references'],
                            'severity': self._calculate_severity(vuln_name, service)
                        }
                        vulnerabilities.append(vulnerability)
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'risk_score': self._calculate_risk_score(vulnerabilities)
        }
    
    def _calculate_severity(self, vuln_name: str, service: Dict) -> str:
        """Calculate vulnerability severity based on service info"""
        high_risk_services = ['telnet', 'ftp', 'rdp']
        medium_risk_services = ['ssh', 'http']
        
        if vuln_name in high_risk_services:
            return 'HIGH'
        elif vuln_name in medium_risk_services:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> int:
        """Calculate overall risk score (0-100)"""
        if not vulnerabilities:
            return 0
        
        score = 0
        for vuln in vulnerabilities:
            if vuln['severity'] == 'HIGH':
                score += 30
            elif vuln['severity'] == 'MEDIUM':
                score += 20
            else:
                score += 10
        
        return min(score, 100)
    
    def is_chat_allowed(self, chat_id: int) -> bool:
        """Check if chat ID is allowed to use the bot"""
        if self.allowed_chat_ids is None:
            return True  # All chats allowed
        return chat_id in self.allowed_chat_ids
    
    async def addchat_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk command /addchat - Admin only"""
        # Check if user is admin
        chat_id = update.effective_chat.id
        
        # Determine admin chat ID
        admin_chat_id = self.admin_chat_id
        if admin_chat_id is None and self.allowed_chat_ids:
            admin_chat_id = min(self.allowed_chat_ids)
        
        if admin_chat_id and chat_id != admin_chat_id:
            await update.message.reply_text(
                "🚫 **Akses Ditolak**\n\nHanya admin yang dapat menambahkan chat ID baru.",
                parse_mode=ParseMode.MARKDOWN
            )
            return
        
        if not context.args:
            await update.message.reply_text(
                "❌ Gunakan: `/addchat <chat_id>`\n\n"
                "Contoh: `/addchat 123456789`\n\n"
                "💡 **Tip:** Untuk mendapatkan chat ID, gunakan bot @userinfobot",
                parse_mode=ParseMode.MARKDOWN
            )
            return
        
        try:
            new_chat_id = int(context.args[0])
            
            # Initialize allowed_chat_ids if None
            if self.allowed_chat_ids is None:
                self.allowed_chat_ids = set()
            
            if new_chat_id in self.allowed_chat_ids:
                await update.message.reply_text(
                    f"ℹ️ Chat ID `{new_chat_id}` sudah ada dalam daftar yang diizinkan.",
                    parse_mode=ParseMode.MARKDOWN
                )
                return
            
            self.allowed_chat_ids.add(new_chat_id)
            
            await update.message.reply_text(
                f"✅ **Chat ID Ditambahkan**\n\n"
                f"Chat ID `{new_chat_id}` berhasil ditambahkan ke daftar yang diizinkan.\n\n"
                f"📊 Total chat yang diizinkan: {len(self.allowed_chat_ids)}",
                parse_mode=ParseMode.MARKDOWN
            )
            
            logger.info(f"Chat ID {new_chat_id} added by admin {chat_id}")
            
        except ValueError:
            await update.message.reply_text(
                "❌ Chat ID harus berupa angka.\n\n"
                "Contoh: `/addchat 123456789`",
                parse_mode=ParseMode.MARKDOWN
            )
    
    async def listchats_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk command /listchats - Admin only"""
        # Check if user is admin
        chat_id = update.effective_chat.id
        
        # Determine admin chat ID
        admin_chat_id = self.admin_chat_id
        if admin_chat_id is None and self.allowed_chat_ids:
            admin_chat_id = min(self.allowed_chat_ids)
        
        if admin_chat_id and chat_id != admin_chat_id:
            await update.message.reply_text(
                "🚫 **Akses Ditolak**\n\nHanya admin yang dapat melihat daftar chat ID.",
                parse_mode=ParseMode.MARKDOWN
            )
            return
        
        if self.allowed_chat_ids is None or len(self.allowed_chat_ids) == 0:
            await update.message.reply_text(
                "📋 **Daftar Chat ID**\n\n"
                "🌐 Mode: **Terbuka untuk semua**\n"
                "Semua chat ID diizinkan menggunakan bot ini.\n\n"
                "💡 Gunakan `/addchat <chat_id>` untuk membatasi akses.",
                parse_mode=ParseMode.MARKDOWN
            )
            return
        
        chat_list = "\n".join([f"• `{cid}`" for cid in sorted(self.allowed_chat_ids)])
        
        await update.message.reply_text(
            f"📋 **Daftar Chat ID yang Diizinkan**\n\n"
            f"{chat_list}\n\n"
            f"📊 Total: {len(self.allowed_chat_ids)} chat\n\n"
            f"💡 Gunakan `/addchat <chat_id>` untuk menambah chat baru.",
            parse_mode=ParseMode.MARKDOWN
        )
    
    async def getchatid_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk command /getchatid - Get current chat ID"""
        chat_id = update.effective_chat.id
        user_id = update.effective_user.id
        chat_type = update.effective_chat.type
        
        await update.message.reply_text(
            f"🆔 **Informasi Chat**\n\n"
            f"**Chat ID:** `{chat_id}`\n"
            f"**User ID:** `{user_id}`\n"
            f"**Chat Type:** `{chat_type}`\n\n"
            f"💡 **Tip:** Berikan Chat ID ini kepada admin untuk mendapatkan akses bot.",
            parse_mode=ParseMode.MARKDOWN
        )
    
    async def check_access(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
        """Middleware to check if user has access to the bot"""
        chat_id = update.effective_chat.id
        
        if not self.is_chat_allowed(chat_id):
            await update.message.reply_text(
                "🚫 **Akses Ditolak**\n\n"
                "Maaf, Anda tidak memiliki izin untuk menggunakan bot ini.\n"
                "Silakan hubungi administrator untuk mendapatkan akses.",
                parse_mode=ParseMode.MARKDOWN
            )
            logger.warning(f"Unauthorized access attempt from chat_id: {chat_id}")
            return False
        
        return True
    
    async def shodan_search(self, query: str, limit: int = 10) -> str:
        """Search Shodan with vulnerability analysis"""
        try:
            results = self.shodan_api.search(query, limit=limit)
            
            if not results['matches']:
                return "❌ Tidak ada hasil ditemukan untuk query tersebut."
            
            response = f"🔍 **Hasil Pencarian Shodan**\n\n"
            response += f"📊 **Total:** {results['total']:,} hasil\n"
            response += f"📋 **Menampilkan:** {len(results['matches'])} hasil teratas\n\n"
            
            for i, result in enumerate(results['matches'][:limit], 1):
                ip = result.get('ip_str', 'N/A')
                port = result.get('port', 'N/A')
                org = result.get('org', 'N/A')
                country = result.get('location', {}).get('country_name', 'N/A')
                product = result.get('product', 'N/A')
                
                response += f"**{i}. {ip}:{port}**\n"
                response += f"🏢 Org: {org}\n"
                response += f"🌍 Country: {country}\n"
                response += f"💻 Product: {product}\n"
                
                # Quick vulnerability check
                vuln_analysis = self.analyze_vulnerabilities({'data': [result]})
                if vuln_analysis['vulnerabilities']:
                    response += f"⚠️ **Vulnerabilities Found:** {vuln_analysis['total_vulnerabilities']}\n"
                    response += f"🎯 **Risk Score:** {vuln_analysis['risk_score']}/100\n"
                
                response += "\n"
            
            return response
            
        except shodan.APIError as e:
            return f"❌ Shodan API Error: {str(e)}"
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    async def shodan_host_info(self, ip: str) -> str:
        """Get detailed host information with vulnerability analysis"""
        try:
            host = self.shodan_api.host(ip)
            
            response = f"🖥️ **Informasi Host: {ip}**\n\n"
            response += f"🏢 **Organisasi:** {host.get('org', 'N/A')}\n"
            response += f"🌍 **Lokasi:** {host.get('country_name', 'N/A')}, {host.get('city', 'N/A')}\n"
            response += f"🌐 **ISP:** {host.get('isp', 'N/A')}\n"
            response += f"📅 **Last Update:** {host.get('last_update', 'N/A')}\n\n"
            
            # Vulnerability Analysis
            vuln_analysis = self.analyze_vulnerabilities(host)
            
            response += f"🛡️ **Security Analysis**\n"
            response += f"⚠️ **Total Vulnerabilities:** {vuln_analysis['total_vulnerabilities']}\n"
            response += f"🎯 **Risk Score:** {vuln_analysis['risk_score']}/100\n\n"
            
            # Show vulnerabilities with remediation
            if vuln_analysis['vulnerabilities']:
                response += "🚨 **Detected Vulnerabilities:**\n\n"
                for vuln in vuln_analysis['vulnerabilities']:
                    response += f"**{vuln['service']} (Port {vuln['port']}) - {vuln['severity']}**\n"
                    response += f"📝 {vuln['description']}\n"
                    response += f"⚠️ **Risks:** {', '.join(vuln['risks'][:2])}\n"
                    response += f"🔧 **Remediation:** {vuln['remediation'][0]}\n\n"
            
            # Open Ports
            response += f"🔌 **Open Ports ({len(host.get('data', []))}):**\n"
            for service in host.get('data', [])[:5]:
                port = service.get('port', 'N/A')
                product = service.get('product', 'Unknown')
                version = service.get('version', '')
                response += f"• **{port}** - {product} {version}\n"
            
            if len(host.get('data', [])) > 5:
                response += f"... dan {len(host.get('data', [])) - 5} port lainnya\n"
            
            return response
            
        except shodan.APIError as e:
            return f"❌ Shodan API Error: {str(e)}"
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    async def shodan_count(self, query: str) -> str:
        """Get count of search results"""
        try:
            result = self.shodan_api.count(query)
            
            response = f"📊 **Statistik Pencarian**\n\n"
            response += f"🔍 **Query:** `{query}`\n"
            response += f"📈 **Total Hasil:** {result['total']:,}\n\n"
            
            if 'facets' in result:
                response += "📋 **Top Countries:**\n"
                for country in result['facets'].get('country', [])[:5]:
                    response += f"• {country['value']}: {country['count']:,}\n"
            
            return response
            
        except shodan.APIError as e:
            return f"❌ Shodan API Error: {str(e)}"
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    async def shodan_api_info(self) -> str:
        """Get Shodan API information"""
        try:
            info = self.shodan_api.info()
            
            response = f"💳 **Informasi API Shodan**\n\n"
            response += f"👤 **Plan:** {info.get('plan', 'N/A')}\n"
            response += f"🔍 **Query Credits:** {info.get('query_credits', 0):,}\n"
            response += f"📊 **Scan Credits:** {info.get('scan_credits', 0):,}\n"
            response += f"🌐 **Monitored IPs:** {info.get('monitored_ips', 0):,}\n"
            
            return response
            
        except shodan.APIError as e:
            return f"❌ Shodan API Error: {str(e)}"
        except Exception as e:
            return f"❌ Error: {str(e)}"
    

    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk command /start"""
        # Check access first
        if not await self.check_access(update, context):
            return
        welcome_text = """
🤖 **Selamat datang di Shodan Security Bot!**

🛡️ **Advanced Vulnerability Analysis**
Bot ini menyediakan analisis keamanan canggih dengan:
🔍 Pencarian device/host menggunakan Shodan
🖥️ Informasi detail host dengan vulnerability analysis
📊 Statistik pencarian dan risk assessment
💳 Monitoring quota API Shodan
🚨 Vulnerability reports dengan remediasi
📄 Export hasil dalam format JSON

**Perintah yang tersedia:**
/help - Bantuan lengkap
/search <query> - Pencarian Shodan
/host <ip> - Info detail host + vulnerability scan
/count <query> - Hitung hasil query
/apiinfo - Info API Shodan
/vulnreport <ip> - Laporan vulnerability lengkap
/json <ip> - Export hasil dalam format JSON

**Contoh penggunaan:**
`/search apache`
`/search port:22 country:ID`
`/host 8.8.8.8`
`/vulnreport 192.168.1.1`
`/json 8.8.8.8`

🛡️ **Fitur Security:** Analisis vulnerability otomatis dengan remediasi!
"""
        
        keyboard = [
            [InlineKeyboardButton("🔍 Pencarian Cepat", callback_data="quick_search")],
            [InlineKeyboardButton("📊 Info API", callback_data="api_info")],
            [InlineKeyboardButton("❓ Bantuan", callback_data="help")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            welcome_text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=reply_markup
        )
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk command /help"""
        # Check access first
        if not await self.check_access(update, context):
            return
        help_text = """
📖 **Bantuan Shodan Bot**

**Perintah Utama:**

🔍 `/search <query>` - Mencari device/host
   Contoh: `/search apache`, `/search port:80`

🖥️ `/host <ip>` - Info detail host berdasarkan IP
   Contoh: `/host 8.8.8.8`

📊 `/count <query>` - Menghitung jumlah hasil
   Contoh: `/count nginx`

💳 `/apiinfo` - Informasi quota API Shodan

🛡️ `/vulnreport <ip>` - Laporan kerentanan detail
   Contoh: `/vulnreport 8.8.8.8`

📄 `/json <ip>` - Export hasil scan ke JSON
   Contoh: `/json 8.8.8.8`

**Command Admin:**
🔐 `/addchat <chat_id>` - Tambah chat ID ke whitelist (Admin only)
📋 `/listchats` - Lihat daftar chat ID yang diizinkan (Admin only)
🆔 `/getchatid` - Dapatkan Chat ID Anda

**Query Shodan yang Berguna:**
• `port:22` - SSH servers
• `port:80` - HTTP servers
• `country:ID` - Device di Indonesia
• `city:Jakarta` - Device di Jakarta
• `org:"PT Telkom"` - Device milik Telkom
• `product:apache` - Apache servers
• `vuln:CVE-2021-44228` - Vulnerable to Log4j

**Operator Query:**
• `AND`, `OR`, `NOT` - Logical operators
• `"exact phrase"` - Pencarian exact
• `net:192.168.1.0/24` - Network range

⚠️ **Catatan Penting:**
- Gunakan bot ini secara bertanggung jawab
- Jangan melakukan scanning yang tidak sah
- Hormati privacy dan keamanan sistem lain
"""
        
        await update.message.reply_text(
            help_text,
            parse_mode=ParseMode.MARKDOWN
        )
    
    async def search_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk command /search"""
        # Check access first
        if not await self.check_access(update, context):
            return
        if not context.args:
            await update.message.reply_text(
                "❌ Gunakan: `/search <query>`\n\n"
                "Contoh: `/search apache` atau `/search port:22 country:ID`",
                parse_mode=ParseMode.MARKDOWN
            )
            return
        
        query = ' '.join(context.args)
        
        # Send "typing" action
        await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
        
        try:
            # Call direct Shodan API search
            result = await self.shodan_search(query, 5)
            
            await update.message.reply_text(
                result,
                parse_mode=ParseMode.MARKDOWN
            )
            
        except Exception as e:
            logger.error(f"Error dalam search command: {str(e)}")
            await update.message.reply_text(
                f"❌ Terjadi error: {str(e)}",
                parse_mode=ParseMode.MARKDOWN
            )
    
    async def host_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk command /host"""
        # Check access first
        if not await self.check_access(update, context):
            return
        if not context.args:
            await update.message.reply_text(
                "❌ Gunakan: `/host <ip_address>`\nContoh: `/host 8.8.8.8`",
                parse_mode=ParseMode.MARKDOWN
            )
            return
        
        ip = context.args[0]
        
        # Kirim pesan loading
        loading_msg = await update.message.reply_text(
            f"🖥️ Menganalisis host: `{ip}`\n⏳ Mohon tunggu...",
            parse_mode=ParseMode.MARKDOWN
        )
        
        try:
            # Call direct Shodan API host info
            result = await self.shodan_host_info(ip)
            
            # Edit pesan loading dengan hasil
            await loading_msg.edit_text(
                result,
                parse_mode=ParseMode.MARKDOWN
            )
            
        except Exception as e:
            await loading_msg.edit_text(
                f"❌ Error: {str(e)}",
                parse_mode=ParseMode.MARKDOWN
            )
    
    async def count_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk command /count"""
        # Check access first
        if not await self.check_access(update, context):
            return
        if not context.args:
            await update.message.reply_text(
                "❌ Gunakan: `/count <query>`\nContoh: `/count nginx`",
                parse_mode=ParseMode.MARKDOWN
            )
            return
        
        query = " ".join(context.args)
        
        # Kirim pesan loading
        loading_msg = await update.message.reply_text(
            f"📊 Menghitung hasil untuk: `{query}`\n⏳ Mohon tunggu...",
            parse_mode=ParseMode.MARKDOWN
        )
        
        try:
            # Call direct Shodan API count
            result = await self.shodan_count(query)
            
            # Edit pesan loading dengan hasil
            await loading_msg.edit_text(
                result,
                parse_mode=ParseMode.MARKDOWN
            )
            
        except Exception as e:
            await loading_msg.edit_text(
                f"❌ Error: {str(e)}",
                parse_mode=ParseMode.MARKDOWN
            )
    
    async def apiinfo_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk command /apiinfo"""
        # Check access first
        if not await self.check_access(update, context):
            return
        # Kirim pesan loading
        loading_msg = await update.message.reply_text(
            "💳 Mengecek informasi API...\n⏳ Mohon tunggu...",
            parse_mode=ParseMode.MARKDOWN
        )
        
        try:
            # Call direct Shodan API info
            result = await self.shodan_api_info()
            
            # Edit pesan loading dengan hasil
            await loading_msg.edit_text(
                result,
                parse_mode=ParseMode.MARKDOWN
            )
            
        except Exception as e:
            await loading_msg.edit_text(
                f"❌ Error: {str(e)}",
                parse_mode=ParseMode.MARKDOWN
            )
    
    async def vulnreport_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk command /vulnreport - Detailed vulnerability report"""
        # Check access first
        if not await self.check_access(update, context):
            return
        if not context.args:
            await update.message.reply_text(
                "❌ Gunakan: `/vulnreport <ip_address>`\n\n"
                "Contoh: `/vulnreport 8.8.8.8`",
                parse_mode=ParseMode.MARKDOWN
            )
            return
        
        ip = context.args[0]
        
        # Send "typing" action
        await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
        
        try:
            # Get host data
            host = self.shodan_api.host(ip)
            
            # Analyze vulnerabilities
            vuln_analysis = self.analyze_vulnerabilities(host)
            
            response = f"🛡️ **Vulnerability Report: {ip}**\n\n"
            response += f"📊 **Risk Assessment:**\n"
            response += f"⚠️ Total Vulnerabilities: {vuln_analysis['total_vulnerabilities']}\n"
            response += f"🎯 Risk Score: {vuln_analysis['risk_score']}/100\n\n"
            
            if vuln_analysis['vulnerabilities']:
                response += "🚨 **Detailed Vulnerability Analysis:**\n\n"
                
                for i, vuln in enumerate(vuln_analysis['vulnerabilities'], 1):
                    response += f"**{i}. {vuln['service']} Service (Port {vuln['port']})**\n"
                    response += f"🔴 **Severity:** {vuln['severity']}\n"
                    response += f"📝 **Description:** {vuln['description']}\n\n"
                    
                    response += f"⚠️ **Security Risks:**\n"
                    for risk in vuln['risks']:
                        response += f"• {risk}\n"
                    
                    response += f"\n🔧 **Remediation Steps:**\n"
                    for step in vuln['remediation']:
                        response += f"• {step}\n"
                    
                    response += f"\n📚 **References:**\n"
                    for ref in vuln['references']:
                        response += f"• {ref}\n"
                    
                    response += "\n" + "="*50 + "\n\n"
            else:
                response += "✅ **No known vulnerabilities detected**\n"
                response += "ℹ️ This doesn't guarantee the host is secure. Regular security audits are recommended.\n"
            
            # Split long messages
            if len(response) > 4000:
                parts = [response[i:i+4000] for i in range(0, len(response), 4000)]
                for part in parts:
                    await update.message.reply_text(
                        part,
                        parse_mode=ParseMode.MARKDOWN
                    )
            else:
                await update.message.reply_text(
                    response,
                    parse_mode=ParseMode.MARKDOWN
                )
            
        except shodan.APIError as e:
            await update.message.reply_text(
                f"❌ Shodan API Error: {str(e)}",
                parse_mode=ParseMode.MARKDOWN
            )
        except Exception as e:
            logger.error(f"Error dalam vulnreport command: {str(e)}")
            await update.message.reply_text(
                f"❌ Terjadi error: {str(e)}",
                parse_mode=ParseMode.MARKDOWN
            )
    
    async def json_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk command /json - Export data in JSON format"""
        # Check access first
        if not await self.check_access(update, context):
            return
        if not context.args:
            await update.message.reply_text(
                "❌ Gunakan: `/json <ip_address>`\n\n"
                "Contoh: `/json 8.8.8.8`",
                parse_mode=ParseMode.MARKDOWN
            )
            return
        
        ip = context.args[0]
        
        # Send "typing" action
        await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
        
        try:
            # Get host data
            host = self.shodan_api.host(ip)
            
            # Analyze vulnerabilities
            vuln_analysis = self.analyze_vulnerabilities(host)
            
            # Create JSON export
            json_data = {
                "scan_info": {
                    "target_ip": ip,
                    "scan_date": host.get('last_update', 'N/A'),
                    "scanner": "Shodan Security Bot"
                },
                "host_info": {
                    "ip": ip,
                    "organization": host.get('org', 'N/A'),
                    "country": host.get('country_name', 'N/A'),
                    "city": host.get('city', 'N/A'),
                    "isp": host.get('isp', 'N/A'),
                    "asn": host.get('asn', 'N/A')
                },
                "security_analysis": {
                    "total_vulnerabilities": vuln_analysis['total_vulnerabilities'],
                    "risk_score": vuln_analysis['risk_score'],
                    "risk_level": "HIGH" if vuln_analysis['risk_score'] >= 70 else "MEDIUM" if vuln_analysis['risk_score'] >= 40 else "LOW"
                },
                "open_ports": [],
                "vulnerabilities": vuln_analysis['vulnerabilities']
            }
            
            # Add open ports info
            for service in host.get('data', []):
                port_info = {
                    "port": service.get('port', 'N/A'),
                    "protocol": service.get('transport', 'N/A'),
                    "service": service.get('_shodan', {}).get('module', 'N/A'),
                    "product": service.get('product', 'N/A'),
                    "version": service.get('version', 'N/A'),
                    "banner": service.get('data', '')[:200] + '...' if len(service.get('data', '')) > 200 else service.get('data', '')
                }
                json_data["open_ports"].append(port_info)
            
            # Format JSON with proper indentation
            json_output = json.dumps(json_data, indent=2, ensure_ascii=False)
            
            # Send as file if too long, otherwise as text
            if len(json_output) > 4000:
                # Create temporary file
                filename = f"shodan_report_{ip.replace('.', '_')}.json"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(json_output)
                
                # Send file
                with open(filename, 'rb') as f:
                    await update.message.reply_document(
                        document=f,
                        filename=filename,
                        caption=f"📄 **JSON Report untuk {ip}**\n🛡️ Risk Score: {vuln_analysis['risk_score']}/100"
                    )
                
                # Clean up
                os.remove(filename)
            else:
                await update.message.reply_text(
                    f"📄 **JSON Export untuk {ip}:**\n\n```json\n{json_output}\n```",
                    parse_mode=ParseMode.MARKDOWN
                )
            
        except shodan.APIError as e:
            await update.message.reply_text(
                f"❌ Shodan API Error: {str(e)}",
                parse_mode=ParseMode.MARKDOWN
            )
        except Exception as e:
            logger.error(f"Error dalam json command: {str(e)}")
            await update.message.reply_text(
                f"❌ Terjadi error: {str(e)}",
                parse_mode=ParseMode.MARKDOWN
            )
    
    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk inline keyboard buttons"""
        # Check access first
        chat_id = update.effective_chat.id
        if not self.is_chat_allowed(chat_id):
            query = update.callback_query
            await query.answer("🚫 Akses ditolak", show_alert=True)
            return
        
        query = update.callback_query
        await query.answer()
        
        if query.data == "quick_search":
            await query.edit_message_text(
                "🔍 **Pencarian Cepat**\n\nPilih salah satu pencarian berikut:",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🌐 Web Servers (port:80)", callback_data="search_port:80")],
                    [InlineKeyboardButton("🔐 SSH Servers (port:22)", callback_data="search_port:22")],
                    [InlineKeyboardButton("🇮🇩 Indonesia Devices", callback_data="search_country:ID")],
                    [InlineKeyboardButton("🔙 Kembali", callback_data="back_main")]
                ])
            )
        
        elif query.data == "api_info":
            loading_msg = await query.edit_message_text(
                "💳 Mengecek informasi API...\n⏳ Mohon tunggu...",
                parse_mode=ParseMode.MARKDOWN
            )
            
            try:
                result = await self.shodan_api_info()
                await query.edit_message_text(
                    result,
                    parse_mode=ParseMode.MARKDOWN
                )
            except Exception as e:
                await query.edit_message_text(
                    f"❌ Error: {str(e)}",
                    parse_mode=ParseMode.MARKDOWN
                )
        
        elif query.data == "help":
            await self.help_command(update, context)
        
        elif query.data.startswith("search_"):
            search_query = query.data.replace("search_", "")
            
            loading_msg = await query.edit_message_text(
                f"🔍 Mencari: `{search_query}`\n⏳ Mohon tunggu...",
                parse_mode=ParseMode.MARKDOWN
            )
            
            try:
                result = await self.shodan_search(search_query, 5)
                await query.edit_message_text(
                    result,
                    parse_mode=ParseMode.MARKDOWN
                )
            except Exception as e:
                await query.edit_message_text(
                    f"❌ Error: {str(e)}",
                    parse_mode=ParseMode.MARKDOWN
                )
        
        elif query.data == "back_main":
            await self.start_command(update, context)
    
    async def unknown_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk pesan yang tidak dikenal"""
        # Check access first
        if not await self.check_access(update, context):
            return
        await update.message.reply_text(
            "❓ Perintah tidak dikenal.\n\nGunakan /help untuk melihat daftar perintah yang tersedia.",
            parse_mode=ParseMode.MARKDOWN
        )
    
    async def setup_bot(self):
        """Setup bot dan handlers"""
        # Buat application
        self.application = Application.builder().token(self.bot_token).build()
        
        # Tambahkan handlers
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("help", self.help_command))
        self.application.add_handler(CommandHandler("search", self.search_command))
        self.application.add_handler(CommandHandler("host", self.host_command))
        self.application.add_handler(CommandHandler("count", self.count_command))
        self.application.add_handler(CommandHandler("apiinfo", self.apiinfo_command))
        self.application.add_handler(CommandHandler("vulnreport", self.vulnreport_command))
        self.application.add_handler(CommandHandler("json", self.json_command))
        self.application.add_handler(CommandHandler("addchat", self.addchat_command))
        self.application.add_handler(CommandHandler("listchats", self.listchats_command))
        self.application.add_handler(CommandHandler("getchatid", self.getchatid_command))
        self.application.add_handler(CallbackQueryHandler(self.button_callback))
        self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.unknown_command))
        
        logger.info("Bot handlers berhasil disetup")
    
    async def run(self):
        """Menjalankan bot"""
        try:
            await self.setup_bot()
            
            logger.info("🤖 Shodan Security Bot dimulai...")
            
            # Initialize and start polling
            await self.application.initialize()
            await self.application.start()
            await self.application.updater.start_polling()
            
            # Keep running until interrupted
            try:
                await asyncio.Event().wait()
            except KeyboardInterrupt:
                logger.info("Bot dihentikan oleh user")
            finally:
                # Proper cleanup
                await self.application.updater.stop()
                await self.application.stop()
                await self.application.shutdown()
            
        except Exception as e:
            logger.error(f"Error menjalankan bot: {str(e)}")
            # Cleanup on error
            if hasattr(self, 'application') and self.application:
                try:
                    await self.application.updater.stop()
                    await self.application.stop()
                    await self.application.shutdown()
                except:
                    pass
            raise

async def main():
    """Main function"""
    try:
        bot = ShodanTelegramBot()
        await bot.run()
    except KeyboardInterrupt:
        logger.info("Bot dihentikan oleh user")
    except Exception as e:
        logger.error(f"Error: {str(e)}")

def run_bot():
    """Run bot with proper event loop handling"""
    try:
        # Check if there's already an event loop running
        loop = asyncio.get_running_loop()
        # If we get here, there's already a loop running
        # Create a new task in the existing loop
        task = loop.create_task(main())
        return task
    except RuntimeError:
        # No event loop running, create a new one
        asyncio.run(main())

if __name__ == "__main__":
    run_bot()