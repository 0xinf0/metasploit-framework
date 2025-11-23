# Mobile Security Lab - State-of-the-Art Mobile Application Security Testing

A comprehensive, production-ready mobile security testing laboratory built on top of the Metasploit Framework, specialized for VPN application security analysis.

## 🚀 Features

### Static Analysis
- **APK Analysis** - Comprehensive Android APK static analysis
  - AndroidManifest.xml parsing
  - Permission analysis (dangerous, normal, custom)
  - Component security (Activities, Services, Receivers, Providers)
  - Certificate extraction and validation
  - String extraction and sensitive data detection
  - Third-party library detection
  - Network security configuration analysis
  - OWASP Mobile Top 10 compliance checking

- **iOS/IPA Analysis** - Complete iOS application analysis
  - Info.plist parsing
  - Entitlements extraction
  - Provisioning profile analysis
  - Binary security analysis (PIE, encryption, stack canaries)
  - Framework detection
  - Privacy manifest checking (iOS 17+)

### VPN-Specific Security Testing
- DNS leak detection
- IP leak detection (IPv4, IPv6, WebRTC)
- Encryption implementation analysis
- Kill switch detection
- Privacy and tracking SDK detection
- Protocol analysis (OpenVPN, WireGuard, IKEv2, etc.)
- Third-party analytics detection

### Dynamic Analysis
- Real device integration (Android via ADB, iOS via libimobiledevice)
- Automated app installation
- Network traffic capture (tcpdump, mitmproxy)
- Runtime behavior monitoring
- API call tracing with Frida
- Screen recording
- VPN leak testing (live)

### Web-Based Interfaces

#### Private Lab GUI (Port 4567)
- Upload and analyze apps
- View analysis queue and progress
- Browse all analyses and reports
- VPN app database management
- Device management
- Settings and configuration

#### Public Report Portal (Port 8080)
- Read-only public access
- Browse published security reports
- VPN app security leaderboard
- Statistics and metrics
- JSON API for integration

### Additional Features
- **VPN App Downloader** - Automatically download popular VPN apps by region
- **MobSF Integration** - Enhanced analysis combining MSF + MobSF
- **Multiple Report Formats** - JSON, HTML, PDF, TXT
- **Automated Analysis Pipeline** - Queue-based job processing
- **RESTful API** - Full API access for automation

## 📋 Requirements

### Core Requirements
```bash
# Ruby
ruby >= 2.7

# Metasploit Framework
metasploit-framework (already included)

# Android Analysis Tools
apktool >= 2.9.2
keytool (Java JDK)
apksigner (Android SDK Build Tools)
zipalign (Android SDK Build Tools)
aapt (Android SDK Build Tools)

# iOS Analysis Tools
plutil (macOS) or plistutil
codesign (macOS)
ideviceinstaller
ideviceinfo
libimobiledevice

# Network Analysis
tcpdump
mitmproxy
wireshark (optional)

# Dynamic Instrumentation
frida
frida-tools

# Optional (for enhanced features)
Mobile Security Framework (MobSF)
apkeep (for APK downloading)
ipatool (for IPA downloading)
```

### Ruby Gems
```bash
gem install sinatra
gem install plist
gem install nokogiri
gem install zip
```

## 🔧 Installation

### 1. Quick Setup Script
```bash
cd /home/user/metasploit-framework/tools/mobile_security_lab
./setup.sh
```

### 2. Manual Installation

#### Install Android Tools
```bash
# Install Android SDK
sudo apt-get install android-sdk

# Or use sdkmanager
sdkmanager "build-tools;34.0.0"
sdkmanager "platform-tools"

# Install apktool
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.2.jar
sudo mv apktool_2.9.2.jar /usr/local/bin/apktool.jar
# Create wrapper script
```

#### Install iOS Tools (macOS)
```bash
brew install libimobiledevice
brew install ideviceinstaller
```

#### Install Frida
```bash
pip3 install frida-tools
```

#### Install MobSF (Optional)
```bash
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF
./setup.sh
```

## 🚀 Quick Start

### 1. Start the Mobile Security Lab

#### Private Lab Interface
```bash
cd tools/mobile_security_lab/web_gui
ruby mobile_lab_server.rb

# Access at: http://localhost:4567
# Default password: change_me_in_production
```

#### Public Report Portal
```bash
cd tools/mobile_security_lab/web_gui
ruby public_portal.rb

# Access at: http://localhost:8080
```

### 2. Command Line Usage

#### Analyze APK (Static)
```bash
msfconsole -q -x "use auxiliary/scanner/mobile/apk_analyzer; set APP_FILE /path/to/app.apk; set OUTPUT_DIR ./reports; run; exit"
```

#### Analyze iOS App
```bash
msfconsole -q -x "use auxiliary/scanner/mobile/ios_analyzer; set IPA_FILE /path/to/app.ipa; set OUTPUT_DIR ./reports; run; exit"
```

#### VPN Security Analysis
```bash
msfconsole -q -x "use auxiliary/scanner/mobile/vpn_analyzer; set APP_FILE /path/to/vpn.apk; set APP_TYPE APK; set VPN_FOCUS true; run; exit"
```

#### Dynamic Analysis (Requires Device)
```bash
# Connect Android device via ADB
adb devices

msfconsole -q -x "use auxiliary/scanner/mobile/dynamic_analyzer; set APP_FILE /path/to/app.apk; set PLATFORM android; set CAPTURE_TRAFFIC true; set VPN_LEAK_TEST true; run; exit"
```

### 3. Download VPN Apps
```bash
cd tools/mobile_security_lab

# Download top VPN apps for US region
./vpn_app_downloader.rb -r us -p both -m 10

# Create download script
./vpn_app_downloader.rb --create-script
./download_vpn_apps.sh
```

### 4. MobSF Integration
```bash
# Start MobSF first
cd Mobile-Security-Framework-MobSF
./run.sh

# Run enhanced analysis
cd tools/mobile_security_lab
./mobsf_integration.rb -f /path/to/vpn.apk --enhanced
```

## 📊 Usage Examples

### Example 1: Analyze Popular VPN App
```bash
# 1. Download VPN app
cd tools/mobile_security_lab
./vpn_app_downloader.rb -r us -p android -m 1

# 2. Run comprehensive VPN analysis
msfconsole -q -x "
  use auxiliary/scanner/mobile/vpn_analyzer;
  set APP_FILE vpn_apps/us/android/NordVPN/NordVPN.apk;
  set APP_TYPE APK;
  set DEEP_SCAN true;
  set VPN_FOCUS true;
  set REPORT_FORMAT HTML;
  run;
  exit
"

# 3. View results in web GUI
# Navigate to http://localhost:4567/analyses
```

### Example 2: Batch Analysis of Multiple VPNs
```bash
# Analyze all downloaded VPN apps
for apk in vpn_apps/us/android/*/*.apk; do
  echo "Analyzing $apk..."
  msfconsole -q -x "
    use auxiliary/scanner/mobile/vpn_analyzer;
    set APP_FILE $apk;
    set APP_TYPE APK;
    run;
    exit
  "
done
```

### Example 3: Dynamic Analysis with Real Device
```bash
# 1. Connect Android device
adb devices

# 2. Run dynamic analysis with VPN leak testing
msfconsole -q -x "
  use auxiliary/scanner/mobile/dynamic_analyzer;
  set APP_FILE /path/to/vpn.apk;
  set PLATFORM android;
  set INSTALL_APP true;
  set CAPTURE_TRAFFIC true;
  set VPN_LEAK_TEST true;
  set FRIDA_HOOK true;
  set RUNTIME_DURATION 600;
  set RECORD_SCREEN true;
  run;
  exit
"
```

## 🏗️ Architecture

```
metasploit-framework/
├── modules/auxiliary/scanner/mobile/
│   ├── apk_analyzer.rb          # Android static analysis
│   ├── ios_analyzer.rb          # iOS static analysis
│   ├── vpn_analyzer.rb          # VPN-specific analysis
│   └── dynamic_analyzer.rb      # Dynamic analysis with devices
│
└── tools/mobile_security_lab/
    ├── web_gui/
    │   ├── mobile_lab_server.rb # Private lab interface
    │   ├── public_portal.rb     # Public report portal
    │   └── views/               # Web templates
    │
    ├── vpn_app_downloader.rb    # VPN app downloader
    ├── mobsf_integration.rb     # MobSF integration
    ├── setup.sh                 # Setup script
    └── README.md               # This file
```

## 🔐 Security Considerations

### Private Lab (Port 4567)
- **Authentication Required** - Basic HTTP authentication
- **Change Default Password** - Set `LAB_PASSWORD` environment variable
- **Firewall** - Restrict access to trusted networks only
- **HTTPS** - Use reverse proxy (nginx) with SSL in production

### Public Portal (Port 8080)
- **Read-Only** - No write or delete operations
- **Sanitized Reports** - Personal data removed from public reports
- **Rate Limiting** - Implement rate limiting in production
- **CDN** - Use CDN for static assets

## 📈 Report Formats

### JSON Report
```json
{
  "metadata": {...},
  "risk_score": 75,
  "security_issues": [...],
  "privacy_issues": [...],
  "vpn_specific": {...},
  "recommendations": [...]
}
```

### HTML Report
- Beautiful, responsive design
- Risk score visualization
- Issue categorization
- OWASP mapping
- Actionable recommendations

### PDF Report
- Professional layout
- Executive summary
- Detailed findings
- Compliance mapping

## 🤝 Integration

### API Access

#### Submit Analysis
```bash
curl -X POST http://localhost:4567/api/v1/analyze \
  -u admin:password \
  -F "file=@app.apk" \
  -F "platform=android" \
  -F "analysis_type=vpn"
```

#### Get Results
```bash
curl -X GET http://localhost:4567/api/v1/results/{job_id} \
  -u admin:password
```

#### Public API
```bash
# List public reports
curl http://localhost:8080/api/v1/reports

# Get specific report
curl http://localhost:8080/api/v1/reports/{report_id}

# VPN leaderboard
curl http://localhost:8080/api/v1/vpn-leaderboard
```

## 🐛 Troubleshooting

### Common Issues

**APK Analysis Fails**
```bash
# Ensure apktool is installed and up to date
apktool --version  # Should be >= 2.9.2

# Check Java is installed
java -version
```

**Device Not Detected**
```bash
# Android
adb devices
adb kill-server && adb start-server

# iOS
idevice_id -l
```

**Frida Connection Issues**
```bash
# Check Frida server is running on device
adb shell "su -c 'ps | grep frida'"

# Restart Frida server
adb shell "su -c 'killall frida-server'"
adb shell "su -c '/data/local/tmp/frida-server &'"
```

## 📝 License

This mobile security lab is part of the Metasploit Framework and follows the same license (BSD-3-Clause).

## 🌟 Credits

- **Metasploit Framework** - Base framework
- **Mobile Security Framework (MobSF)** - Enhanced analysis integration
- **OWASP Mobile Top 10** - Security standards
- **Frida** - Dynamic instrumentation

## 📧 Support

For issues, questions, or contributions:
- GitHub Issues: [metasploit-framework/issues](https://github.com/rapid7/metasploit-framework/issues)
- Documentation: `/tools/mobile_security_lab/docs/`

---

**Mobile Security Lab** - Making mobile security testing accessible and comprehensive.
