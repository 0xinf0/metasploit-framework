#!/bin/bash
##
# Mobile Security Lab - Installation Verification
##

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}========================================"
echo "Mobile Security Lab - Installation Check"
echo -e "========================================${NC}"
echo ""

MISSING_TOOLS=()
INSTALLED_TOOLS=()

check_tool() {
    local tool=$1
    local cmd=$2

    echo -n "Checking $tool... "

    if eval "$cmd" &>/dev/null; then
        echo -e "${GREEN}✓ Installed${NC}"
        INSTALLED_TOOLS+=("$tool")
        return 0
    else
        echo -e "${RED}✗ Missing${NC}"
        MISSING_TOOLS+=("$tool")
        return 1
    fi
}

# Core Requirements
echo -e "${BLUE}Core Requirements:${NC}"
check_tool "Ruby" "ruby --version"
check_tool "Java" "java -version"
check_tool "Bundler" "bundle --version"
echo ""

# Android Tools
echo -e "${BLUE}Android Analysis Tools:${NC}"
check_tool "apktool" "apktool --version"
check_tool "aapt" "aapt version"
check_tool "keytool" "keytool -help"
check_tool "adb" "adb version"
check_tool "zipalign" "zipalign"
check_tool "apksigner" "apksigner --version"
echo ""

# Optional Tools
echo -e "${BLUE}Optional Tools:${NC}"
check_tool "Frida" "frida --version"
check_tool "mitmproxy" "mitmdump --version"
check_tool "tcpdump" "tcpdump --version"
echo ""

# iOS Tools (macOS only)
if [ "$(uname)" == "Darwin" ]; then
    echo -e "${BLUE}iOS Tools (macOS):${NC}"
    check_tool "ideviceinfo" "ideviceinfo --version"
    check_tool "ideviceinstaller" "ideviceinstaller --version"
    echo ""
fi

# Ruby Gems
echo -e "${BLUE}Ruby Gems:${NC}"
check_tool "sinatra" "ruby -e 'require \"sinatra\"'"
check_tool "nokogiri" "ruby -e 'require \"nokogiri\"'"
check_tool "plist" "ruby -e 'require \"plist\"'"
check_tool "zip" "ruby -e 'require \"zip\"'"
echo ""

# Check MSF Modules
echo -e "${BLUE}MSF Modules:${NC}"
MSF_DIR="/home/user/metasploit-framework/modules/auxiliary/scanner/mobile"
check_tool "APK Analyzer" "test -f $MSF_DIR/apk_analyzer.rb"
check_tool "iOS Analyzer" "test -f $MSF_DIR/ios_analyzer.rb"
check_tool "VPN Analyzer" "test -f $MSF_DIR/vpn_analyzer.rb"
check_tool "Dynamic Analyzer" "test -f $MSF_DIR/dynamic_analyzer.rb"
echo ""

# Check Web GUI
echo -e "${BLUE}Web Interface:${NC}"
WEB_DIR="/home/user/metasploit-framework/tools/mobile_security_lab/web_gui"
check_tool "Private Lab Server" "test -f $WEB_DIR/mobile_lab_server.rb"
check_tool "Public Portal" "test -f $WEB_DIR/public_portal.rb"
echo ""

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Installed: ${GREEN}${#INSTALLED_TOOLS[@]}${NC}"
echo -e "Missing: ${RED}${#MISSING_TOOLS[@]}${NC}"
echo ""

if [ ${#MISSING_TOOLS[@]} -eq 0 ]; then
    echo -e "${GREEN}✓ All tools installed! Ready to analyze mobile apps.${NC}"
    echo ""
    echo -e "${BLUE}Next steps:${NC}"
    echo "1. Download a test APK:"
    echo "   wget https://f-droid.org/repo/org.fdroid.fdroid_1016050.apk"
    echo ""
    echo "2. Run standalone test:"
    echo "   ./test_apk_analyzer.rb fdroid.apk"
    echo ""
    echo "3. Start web interface:"
    echo "   cd web_gui && LAB_PASSWORD='test123' ruby mobile_lab_server.rb"
else
    echo -e "${RED}✗ Missing tools. Please install:${NC}"
    for tool in "${MISSING_TOOLS[@]}"; do
        echo "  - $tool"
    done
    echo ""
    echo "See INSTALLATION.md for detailed installation instructions."
fi

echo ""
echo -e "${BLUE}========================================${NC}"
