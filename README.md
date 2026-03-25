# 🔍 InvestigateR - Fast Threat Intelligence Chrome Extension

> **v1.1.0** - Threat Intelligence Tool for Security Professionals

A high-performance Chrome extension for SOC analysts, security researchers, and incident responders. Query threat intelligence sources in parallel for instant analysis of IPs, domains, URLs, and file hashes.

<img width="1185" height="708" alt="secret-message" src="https://github.com/user-attachments/assets/838c33e1-aac1-4863-ab09-3a502cb93356" />

## ✨ Key Features

- **⚡ Lightning Fast** - All queries execute in parallel for maximum speed
- **🎯 Real-Time Results** - Results appear instantly as they arrive
- **🎨 Modern Dark UI** - Professional interface optimized for analysts
- **🖱️ Context Menu** - Right-click any text to investigate instantly
- **🕵️ Passive Mode** - Stealth investigation without alerting targets
- **🔄 Smart Filtering** - Auto-show only relevant tools for each observable type
- **📦 Batch Processing** - Analyze multiple observables simultaneously
- **🔐 Privacy-First** - All API keys stored locally, zero telemetry

---

## 📑 Table of Contents

- [Supported Tools](#-supported-tools)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Getting API Keys](#-getting-api-keys)
- [Passive Mode](#-passive-mode-stealth-investigation)
- [Technical Details](#-technical-architecture)
- [Security & Privacy](#-security--privacy)
- [Contributing](#-contributing)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)

---

## 🛠️ Supported Tools

### 🔑 Premium Tools (Free API Keys Required)
| Tool | IP | Domain | URL | Hash | Description |
|------|:--:|:------:|:---:|:----:|-------------|
| **VirusTotal** | ✓ | ✓ | ✓ | ✓ | Multi-engine malware scanning |
| **AbuseIPDB** | ✓ | - | - | - | IP reputation and abuse reports |
| **AlienVault OTX** | ✓ | ✓ | - | ✓ | Open Threat Exchange intelligence |
| **URLScan.io** | - | ✓ | ✓ | - | URL scanning and screenshot analysis |
| **IPInfo** | ✓ | - | - | - | Geolocation, ASN, ISP data |
| **Hybrid Analysis** | - | - | - | ✓ | Sandbox malware analysis |

### 🆓 Free Tools (No API Key Required)
| Tool | IP | Domain | URL | Hash | Description |
|------|:--:|:------:|:---:|:----:|-------------|
| **Shodan IDB** | ✓ | - | - | - | Open ports & vulnerabilities |
| **PhishTank** | - | - | ✓ | - | Phishing URL database |
| **ThreatFox** | ✓ | ✓ | - | ✓ | IOC database (Abuse.ch) |
| **MalwareBazaar** | - | - | - | ✓ | Malware hash database |
| **URLhaus** | - | ✓ | ✓ | - | Malicious URL database |
| **OpenPhish** | - | - | ✓ | - | Phishing threat feed |
| **SANS ISC** | ✓ | - | - | - | Internet Storm Center data |
| **GreyNoise** | ✓ | - | - | - | Internet noise detection |
| **WHOIS** | ✓ | ✓ | - | - | Domain registration info |
| **DNS Records** | - | ✓ | - | - | DNS lookup (A, MX, NS, TXT) |
| **IP Blocklists** | ✓ | - | - | - | Multiple IP reputation lists |
| **Domain Blocklists** | - | ✓ | - | - | Multiple domain blocklists |

---

## 🚀 Installation

### Quick Install (2 Minutes)

**1. Download Extension**
```bash
git clone https://github.com/yourusername/investigater-chrome.git
cd investigater-chrome
```

**2. Load in Chrome**
1. Open `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `investigater-chrome` folder
5. ✅ Extension installed!

**3. Test It (No API Keys Needed)**
1. Click the InvestigateR icon
2. Enter: `8.8.8.8`
3. Click **🔍 Investigate**
4. Watch results appear in real-time!

**4. Configure API Keys (Optional)**

14 tools work free immediately! For premium tools:

1. Click **⚙️ Settings**
2. Enter API keys (see [Getting API Keys](#-getting-api-keys) below)
3. Click **💾 Save Settings**
4. Click **🧪 Test API Keys** to verify

---

## 🎯 Quick Start

1. **Download Extension**
   ```bash
   git clone https://github.com/yourusername/investigater-chrome.git
   cd investigater-chrome
   ```

2. **Load in Chrome**
   - Open `chrome://extensions/`
   - Enable **Developer mode** (top right toggle)
   - Click **Load unpacked**
   - Select the `investigater-chrome` folder

3. **Configure API Keys** (Optional)
   - Click the extension icon in your toolbar
   - Click **⚙️ Settings**
   - Enter API keys for premium tools
   - Click **💾 Save Settings**

### First Investigation

Try these free tools immediately (no API key needed):

1. Click the InvestigateR icon
2. Enter: `8.8.8.8`
3. The extension auto-selects compatible tools
4. Click **🔍 Investigate**
5. Watch results appear in real-time!

## 📖 Usage Guide

### Basic Investigation

1. **Single Observable**
   ```
   google.com
   ```

2. **Multiple Observables** (batch analysis)
   ```
   8.8.8.8
   google.com
   44d88612fea8a8f36de82e1278abb02f
   ```

### Advanced Features

#### 🎯 **Smart Tool Filtering**
- Extension auto-detects observable types
- Shows only compatible tools
- Example: Enter IP → Only IP-compatible tools visible

#### 🕵️ **Passive Mode** (Stealth Investigation)
- Enable in Settings to avoid alerting targets
- Disables active DNS lookups and reverse DNS
- Perfect for investigating live threats

#### ⌨️ **Keyboard Shortcuts**
- `Ctrl+Enter` - Submit investigation
- Quick select/deselect all tools with buttons

## 🔑 Getting Free API Keys

### VirusTotal (Highly Recommended)
1. Visit https://www.virustotal.com/gui/my-apikey
2. Sign up (free account)
3. Copy your API key
4. Paste in Settings

### AbuseIPDB
1. Visit https://www.abuseipdb.com/account/api
2. Create free account
3. Generate API key
4. Add to Settings

### AlienVault OTX
1. Visit https://otx.alienvault.com/api
2. Sign up free
3. Find API key in your profile
4. Configure in Settings

### URLScan.io
1. Visit https://urlscan.io/user/profile/
2. Create account
3. Generate API key
4. Add to extension

### Other API Keys
- **IPInfo**: https://ipinfo.io/signup
- **Hybrid Analysis**: https://www.hybrid-analysis.com/apikeys/info
- **URLquery**: Contact for API access
- **Shodan**: https://account.shodan.io/ (optional, free tier available)
- **GreyNoise**: https://viz.greynoise.io/signup (community API free)

## 💡 Use Cases & Examples

### 🛡️ SOC Analyst Workflow
```
# Daily threat hunting
suspicious-ip-from-firewall.log
unknown-domain-from-proxy.log
```
**Benefit**: Instant multi-source reputation check

### 🔍 Incident Response
```
# Phishing investigation
https://suspicious-login-page.com
phishing-domain.net
attacker-ip-address
```
**Benefit**: Complete infrastructure analysis in seconds

### 🧪 Malware Analysis
```
# Sample analysis
c0d0f2dce4675bc0c6b2c7f5f7e9c8e3
malware-c2-domain.com
192.168.1.100
```
**Benefit**: Cross-reference IOCs across 20+ sources

### 🌐 Threat Intelligence Enrichment
```
# Campaign tracking
# APT28 Infrastructure
45.67.89.12
evil-domain.ru
backup-c2.com
```
**Benefit**: Automated enrichment for reports

**Benefit**: Automated enrichment for reports

## 🏗️ Technical Architecture

### Performance Optimization

- **Parallel Execution**: All queries use `Promise.all()` for concurrent execution
- **Progressive Rendering**: Results display immediately as received
- **Client-Side Processing**: Direct API queries eliminate proxy latency
- **Smart Caching**: Chrome local storage for instant API key retrieval
- **Lightweight Service Worker**: Minimal background processing

### File Structure
```
investigater-chrome/
├── manifest.json          # Extension configuration (Manifest V3)
├── popup.html            # Main UI interface
├── popup.css             # Dark theme styling
├── popup.js              # Query engine & result rendering (3000+ lines)
├── background.js         # Service worker for context menu
├── settings.html         # API key configuration page
├── settings.js           # Settings management
├── icons/                # Extension icons (16px, 48px, 128px)
├── README.md             # This file
├── LICENSE               # MIT License
└── .gitignore
```

### Observable Type Detection
```javascript
Regex Patterns:
- IPv4: (\d{1,3}\.){3}\d{1,3}
- IPv6: ([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}
- URL: ^https?://
- Hash: ^[a-fA-F0-9]{32,64}$ (MD5/SHA1/SHA256)
- Domain: Valid TLD with DNS-compliant format
```

### Chrome Permissions Used
- `storage` - Save API keys locally
- `contextMenus` - Right-click investigation feature
- `activeTab` - Access selected text on current tab
- `host_permissions: https://*/*` - Query TI APIs

## 🕵️ Passive Mode (Stealth Investigation)

When investigating live attacker infrastructure, you need to avoid alerting them. **Passive Mode** ensures your investigation leaves no traces.

### What Gets Disabled
- ❌ **DNS Records** - No live DNS queries to target nameservers
- ❌ **Auto-Resolve IP** - No reverse DNS lookups

### What Still Works (20+ Tools)
- ✅ All database lookups (VirusTotal, AbuseIPDB, etc.)
- ✅ All threat feeds (ThreatFox, PhishTank, etc.)
- ✅ All reputation lists and blocklists
- ✅ Certificate transparency logs (crt.sh)
- ✅ Historical data (Wayback Machine)

**Enable in Settings** → Check "🕵️ Passive Mode"

## 🎨 Smart Tool Filtering

The extension intelligently shows/hides tools based on what you're investigating:

| You Enter | Tools Shown | Tools Hidden |
|-----------|-------------|--------------|
| `8.8.8.8` | 10 IP tools | 10 non-IP tools |
| `example.com` | 10 domain tools | 10 non-domain tools |
| `https://...` | 6 URL tools | 14 non-URL tools |
| `abc123...` (hash) | 5 hash tools | 15 non-hash tools |
| Mixed types | Union of all compatible | Incompatible only |

**Result**: Cleaner interface, faster selection, fewer errors

## 🚧 Roadmap & Future Features

- [ ] Export results to JSON/CSV/PDF
- [ ] Query history and caching
- [ ] Custom tool plugins
- [ ] Visual relationship graphs
- [ ] Batch import from CSV/JSON files
- [ ] Chrome Web Store publication
- [ ] Firefox/Edge compatibility
- [ ] API rate limit management
- [ ] Customizable risk scoring
- [ ] Integration with SIEM platforms

## 🤝 Contributing

Contributions are welcome! Here's how to add a new TI tool:

### Adding a Tool (5-minute guide)

1. **Edit `popup.js`** - Add to `TOOL_CONFIGS`:
```javascript
newtool: {
  types: ['ip', 'domain', 'url', 'hash'],  // Supported types
  requiresKey: true,  // or false for free tools
  query: async (observable, type, apiKey) => {
    const response = await fetch(`https://api.example.com/${observable}`, {
      headers: { 'Authorization': `Bearer ${apiKey}` }
    });
    const data = await response.json();
    return {
      status: 'success',
      data: {
        result: data.result,
        url: `https://example.com/lookup/${observable}`
      }
    };
  }
}
```

2. **Edit `popup.html`** - Add checkbox in tool list:
```html
<label class="tool-item" data-tool="newtool" data-types="ip,domain" data-section="api">
  <input type="checkbox" class="tool-checkbox" value="newtool" checked>
  <span class="tool-name">New Tool</span>
</label>
```

3. **Edit `settings.html`** - Add API key field (if needed):
```html
<input type="password" id="newtool" placeholder="Enter API key">
```

4. **Test** - Load extension and verify it works!

### Development Setup
```bash
git clone https://github.com/yourusername/investigater-chrome.git
cd investigater-chrome
# Load in Chrome as unpacked extension
# Make changes, reload extension (chrome://extensions)
```

## 📝 License

**MIT License** - See [LICENSE](LICENSE) file

You are free to:
- ✓ Use commercially
- ✓ Modify
- ✓ Distribute
- ✓ Private use

## ⚠️ Legal Disclaimer

**InvestigateR is intended for authorized security research ONLY:**

✅ **Authorized Use:**
- SOC operations and threat hunting
- Incident response activities
- Security research on owned/authorized systems
- Threat intelligence analysis
- Defensive security operations

❌ **Unauthorized Use Prohibited:**
- Attacking systems without permission
- Unauthorized reconnaissance
- Stalking or harassment
- Any illegal activities

**By using this tool, you agree to use it responsibly and legally. The authors assume no liability for misuse.**

## 🙏 Acknowledgments

Special thanks to these excellent threat intelligence providers:

- **VirusTotal** - Multi-engine malware scanning
- **AbuseIPDB** - IP abuse reporting
- **AlienVault OTX** - Open Threat Exchange
- **URLScan.io** - URL analysis service
- **Shodan** - Internet-wide scanning
- **PhishTank** - Phishing database
- **Abuse.ch** - ThreatFox, MalwareBazaar, URLhaus
- **SANS ISC** - Internet Storm Center
- **GreyNoise** - Internet noise detection
- **IPInfo** - IP geolocation service
- **Hybrid Analysis** - Malware sandbox
- **OpenPhish** - Phishing feed

## 📧 Support & Contact

- **Security Issues**: Please report privately

---

**⭐ Star this repo if you find it useful!**

**Built with ❤️ for the security community**
