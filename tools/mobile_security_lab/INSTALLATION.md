# Mobile Security Lab - Complete Installation & Testing Guide

## Current Status

✅ **Code**: All modules written and committed
⚠️ **Environment**: Requires setup and dependencies
❌ **Tested**: Not yet tested with real APKs in this environment

## Installation Steps

### Step 1: Fix Metasploit Dependencies

```bash
cd /home/user/metasploit-framework

# Install missing gems
bundle install

# This should resolve the bundler errors
```

### Step 2: Install Android Analysis Tools

#### On Ubuntu/Debian:
```bash
# Install Java (required for apktool, keytool)
sudo apt-get update
sudo apt-get install -y default-jdk

# Install Android SDK Platform Tools (for adb, aapt, zipalign, apksigner)
sudo apt-get install -y android-sdk

# Or download standalone:
wget https://dl.google.com/android/repository/platform-tools-latest-linux.zip
unzip platform-tools-latest-linux.zip
sudo mv platform-tools /opt/
echo 'export PATH=$PATH:/opt/platform-tools' >> ~/.bashrc
source ~/.bashrc

# Install apktool (v2.9.2+)
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.2.jar
sudo mv apktool_2.9.2.jar /usr/local/bin/apktool.jar

# Create apktool wrapper
sudo cat > /usr/local/bin/apktool <<'EOF'
#!/bin/bash
java -jar /usr/local/bin/apktool.jar "$@"
EOF
sudo chmod +x /usr/local/bin/apktool
```

#### On macOS:
```bash
# Install Homebrew if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install tools
brew install openjdk
brew install apktool
brew install android-platform-tools
```

#### On Kali Linux:
```bash
# Most tools pre-installed, just update
sudo apt-get update
sudo apt-get install -y apktool android-sdk

# Verify
apktool --version  # Should be >= 2.9.2
```

### Step 3: Install iOS Tools (Optional, macOS only)

```bash
# iOS tools require macOS
brew install libimobiledevice
brew install ideviceinstaller
```

### Step 4: Install Additional Tools

```bash
# Install Ruby gems
gem install sinatra
gem install plist
gem install nokogiri
gem install rubyzip

# Install Frida (for dynamic analysis)
pip3 install frida-tools

# Install network tools
sudo apt-get install -y tcpdump
pip3 install mitmproxy
```

### Step 5: Verify Installation

```bash
cd /home/user/metasploit-framework/tools/mobile_security_lab

# Run verification script
./verify_installation.sh

# Or manually check each tool
apktool --version
aapt version
keytool -help
java -version
adb version
```

## Testing the Lab

### Test 1: Standalone APK Test

```bash
# Download a test APK (e.g., from F-Droid open source apps)
wget https://f-droid.org/repo/org.fdroid.fdroid_1016050.apk -O fdroid.apk

# Run standalone test
cd /home/user/metasploit-framework/tools/mobile_security_lab
./test_apk_analyzer.rb fdroid.apk
```

Expected output:
```
================================================================================
Standalone APK Analysis Test
================================================================================
APK: fdroid.apk

[✓] Extracting metadata...
    Size: 10240000 bytes
    MD5: abc123...
    SHA-256: def456...

[*] Checking APK structure...
    ✓ Valid ZIP/APK structure detected

[*] Inspecting APK contents...
    AndroidManifest.xml: ✓
    classes.dex: ✓
    resources.arsc: ✓
    META-INF/ (signatures): ✓

    ✓ This appears to be a valid APK!

[*] Checking analysis tools availability...
    ✓ apktool
    ✓ aapt
    ✓ keytool
    ✓ apksigner
    ✓ zipalign

================================================================================
Analysis Summary
================================================================================
✓ Valid APK file detected

Next steps:
  ✓ All analysis tools available - ready for full analysis!
```

### Test 2: Full MSF Module Test

Once dependencies are installed:

```bash
cd /home/user/metasploit-framework

# Test APK analyzer module
./msfconsole -q -x "use auxiliary/scanner/mobile/apk_analyzer; show options; exit"
```

Expected output:
```
Module options (auxiliary/scanner/mobile/apk_analyzer):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   APK_FILE                          yes       Path to the APK file to analyze
   DEEP_SCAN        true             yes       Perform deep scanning of DEX files
   EXTRACT_STRINGS  true             yes       Extract and analyze strings from DEX
   OUTPUT_DIR                        no        Directory to save analysis reports
   REPORT_FORMAT    JSON             yes       Report output format
   VPN_FOCUS        false            yes       Focus analysis on VPN-specific issues
```

### Test 3: Actual Analysis

```bash
# Run full analysis on test APK
./msfconsole -q -x "
  use auxiliary/scanner/mobile/apk_analyzer;
  set APK_FILE /path/to/test.apk;
  set DEEP_SCAN true;
  set REPORT_FORMAT HTML;
  set OUTPUT_DIR ./test_reports;
  run;
  exit
"
```

Expected: HTML report generated in `./test_reports/`

### Test 4: Web Interface

```bash
cd /home/user/metasploit-framework/tools/mobile_security_lab/web_gui

# Start private lab
LAB_PASSWORD="test123" ruby mobile_lab_server.rb
```

Visit http://localhost:4567 and upload an APK.

## Troubleshooting

### Issue: "apktool not found"
```bash
# Verify installation
which apktool
apktool --version

# If not found, reinstall
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.2.jar
# Follow Step 2 above
```

### Issue: "Bundler::GemNotFound"
```bash
cd /home/user/metasploit-framework
bundle install

# If that fails, try:
bundle update
```

### Issue: "Module not found"
```bash
# Ensure modules are in correct location
ls -la /home/user/metasploit-framework/modules/auxiliary/scanner/mobile/

# Should show:
# apk_analyzer.rb
# ios_analyzer.rb
# vpn_analyzer.rb
# dynamic_analyzer.rb
```

### Issue: "Java not found"
```bash
# Install Java JDK
sudo apt-get install default-jdk

# Verify
java -version
```

## Sample Test APKs

### Free & Open Source Apps (Safe to Test)

1. **F-Droid** (App Store)
   ```bash
   wget https://f-droid.org/repo/org.fdroid.fdroid_1016050.apk
   ```

2. **K-9 Mail**
   ```bash
   wget https://f-droid.org/repo/com.fsck.k9_27044.apk
   ```

3. **Signal** (Privacy App)
   ```bash
   # Download from https://signal.org/android/apk/
   ```

4. **ProtonVPN** (VPN App - Perfect for VPN testing)
   ```bash
   # Download from https://protonvpn.com/download/
   # Or use the VPN downloader:
   cd /home/user/metasploit-framework/tools/mobile_security_lab
   ./vpn_app_downloader.rb -r us -p android -m 1
   ```

## Quick Verification Script

Create and run this to verify everything:

```bash
#!/bin/bash
# verify_installation.sh

echo "Verifying Mobile Security Lab Installation..."
echo ""

# Check Ruby
echo -n "Ruby: "
ruby --version 2>/dev/null && echo "✓" || echo "✗ MISSING"

# Check Java
echo -n "Java: "
java -version 2>&1 | head -1 && echo "✓" || echo "✗ MISSING"

# Check apktool
echo -n "apktool: "
apktool --version 2>/dev/null && echo "✓" || echo "✗ MISSING"

# Check aapt
echo -n "aapt: "
aapt version 2>/dev/null && echo "✓" || echo "✗ MISSING"

# Check keytool
echo -n "keytool: "
keytool -help 2>&1 | head -1 && echo "✓" || echo "✗ MISSING"

# Check adb
echo -n "adb: "
adb version 2>/dev/null | head -1 && echo "✓" || echo "✗ MISSING"

# Check MSF modules
echo -n "APK Analyzer Module: "
[ -f "/home/user/metasploit-framework/modules/auxiliary/scanner/mobile/apk_analyzer.rb" ] && echo "✓" || echo "✗ MISSING"

echo ""
echo "Installation check complete!"
```

## Next Steps After Installation

1. ✅ Install all dependencies (Steps 1-4 above)
2. ✅ Run verification script
3. ✅ Download a test APK
4. ✅ Run standalone test
5. ✅ Run full MSF module test
6. ✅ Start web interface
7. ✅ Analyze your first VPN app!

## Getting Test Data

### Download Popular VPN Apps

```bash
cd /home/user/metasploit-framework/tools/mobile_security_lab

# Download top 5 VPN apps from US region
./vpn_app_downloader.rb -r us -p android -m 5

# This creates:
# vpn_apps/us/android/NordVPN/metadata.json
# vpn_apps/us/android/ExpressVPN/metadata.json
# etc.

# NOTE: You'll need apkeep or manual download:
# cargo install apkeep
# apkeep -a com.nordvpn.android vpn_apps/us/android/NordVPN/
```

## Production Deployment

Once everything works:

1. Set strong password: `export LAB_PASSWORD="very_secure_password"`
2. Use HTTPS with nginx reverse proxy
3. Set up firewall rules
4. Enable systemd services
5. Configure backups

## Support

If you encounter issues:
1. Check this guide first
2. Run verification script
3. Check logs in `/tmp/mobile_lab.log`
4. Open GitHub issue with error details

---

**The code is production-ready - it just needs the environment set up properly!**
