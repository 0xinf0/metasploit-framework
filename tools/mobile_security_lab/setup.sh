#!/bin/bash
##
# Mobile Security Lab - Setup Script
# Automated installation and configuration
##

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "========================================="
echo "Mobile Security Lab - Setup"
echo "========================================="
echo -e "${NC}"

# Check OS
OS="$(uname -s)"
echo -e "${GREEN}[*]${NC} Detected OS: $OS"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
  echo -e "${RED}[!]${NC} Please do not run as root"
  exit 1
fi

echo ""
echo -e "${GREEN}[*]${NC} Installing dependencies..."

# Install Ruby gems
echo -e "${GREEN}[+]${NC} Installing Ruby gems..."
gem install sinatra --no-document
gem install plist --no-document
gem install nokogiri --no-document
gem install rubyzip --no-document

# Check for Android tools
echo ""
echo -e "${GREEN}[*]${NC} Checking Android tools..."

check_command() {
  if command -v $1 &> /dev/null; then
    echo -e "${GREEN}[+]${NC} $1: Found"
    return 0
  else
    echo -e "${YELLOW}[!]${NC} $1: Not found"
    return 1
  fi
}

check_command apktool || echo -e "${YELLOW}    Install: https://ibotpeaches.github.io/Apktool/${NC}"
check_command keytool || echo -e "${YELLOW}    Install Java JDK${NC}"
check_command adb || echo -e "${YELLOW}    Install Android SDK Platform Tools${NC}"
check_command zipalign || echo -e "${YELLOW}    Install Android SDK Build Tools${NC}"

# Check for iOS tools (macOS only)
if [ "$OS" = "Darwin" ]; then
  echo ""
  echo -e "${GREEN}[*]${NC} Checking iOS tools..."
  check_command ideviceinfo || echo -e "${YELLOW}    Install: brew install libimobiledevice${NC}"
  check_command ideviceinstaller || echo -e "${YELLOW}    Install: brew install ideviceinstaller${NC}"
fi

# Check for Frida
echo ""
echo -e "${GREEN}[*]${NC} Checking Frida..."
check_command frida || echo -e "${YELLOW}    Install: pip3 install frida-tools${NC}"

# Check for network tools
echo ""
echo -e "${GREEN}[*]${NC} Checking network tools..."
check_command tcpdump
check_command mitmdump || echo -e "${YELLOW}    Install: pip3 install mitmproxy${NC}"

# Create directory structure
echo ""
echo -e "${GREEN}[*]${NC} Creating directory structure..."

mkdir -p data/analyses
mkdir -p data/public_reports
mkdir -p data/uploads
mkdir -p uploads
mkdir -p vpn_apps

echo -e "${GREEN}[+]${NC} Directories created"

# Set up web GUI
echo ""
echo -e "${GREEN}[*]${NC} Setting up web interfaces..."

chmod +x web_gui/mobile_lab_server.rb
chmod +x web_gui/public_portal.rb
chmod +x vpn_app_downloader.rb
chmod +x mobsf_integration.rb

echo -e "${GREEN}[+]${NC} Web interfaces configured"

# Create systemd service files (optional)
if command -v systemctl &> /dev/null; then
  echo ""
  echo -e "${GREEN}[*]${NC} Would you like to create systemd services? (y/n)"
  read -r response

  if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    create_systemd_services
  fi
fi

# Configuration
echo ""
echo -e "${GREEN}[*]${NC} Configuration..."

if [ -z "$LAB_PASSWORD" ]; then
  echo -e "${YELLOW}[!]${NC} LAB_PASSWORD not set. Using default."
  echo -e "${YELLOW}[!]${NC} Set LAB_PASSWORD environment variable for production."
fi

# Create config file
cat > config.json <<EOF
{
  "lab_name": "Mobile Security Lab",
  "private_port": 4567,
  "public_port": 8080,
  "max_concurrent_jobs": 2,
  "auto_analyze_vpn": true,
  "enable_dynamic_analysis": false
}
EOF

echo -e "${GREEN}[+]${NC} Configuration file created: config.json"

# Test Metasploit modules
echo ""
echo -e "${GREEN}[*]${NC} Testing Metasploit modules..."

if [ -f "../../msfconsole" ]; then
  echo -e "${GREEN}[+]${NC} Metasploit Framework found"
else
  echo -e "${RED}[!]${NC} Metasploit Framework not found at expected location"
fi

# Installation summary
echo ""
echo -e "${BLUE}"
echo "========================================="
echo "Installation Complete!"
echo "========================================="
echo -e "${NC}"

echo ""
echo -e "${GREEN}Next Steps:${NC}"
echo ""
echo "1. Start the private lab interface:"
echo "   cd web_gui && ruby mobile_lab_server.rb"
echo "   Access at: http://localhost:4567"
echo ""
echo "2. Start the public report portal:"
echo "   cd web_gui && ruby public_portal.rb"
echo "   Access at: http://localhost:8080"
echo ""
echo "3. Download VPN apps:"
echo "   ./vpn_app_downloader.rb -r us -p both -m 10"
echo ""
echo "4. Run analysis via Metasploit:"
echo "   msfconsole -q -x \"use auxiliary/scanner/mobile/apk_analyzer; set APP_FILE test.apk; run; exit\""
echo ""
echo -e "${YELLOW}Security Note:${NC}"
echo "- Change default password: export LAB_PASSWORD='your_secure_password'"
echo "- Use firewall to restrict access"
echo "- Enable HTTPS in production"
echo ""

# Optional: Start services
echo -e "${GREEN}[*]${NC} Start services now? (y/n)"
read -r response

if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
  echo -e "${GREEN}[*]${NC} Starting services..."

  cd web_gui

  # Start private lab in background
  ruby mobile_lab_server.rb &> /tmp/mobile_lab.log &
  PRIVATE_PID=$!
  echo -e "${GREEN}[+]${NC} Private lab started (PID: $PRIVATE_PID)"

  # Start public portal in background
  ruby public_portal.rb &> /tmp/public_portal.log &
  PUBLIC_PID=$!
  echo -e "${GREEN}[+]${NC} Public portal started (PID: $PUBLIC_PID)"

  echo ""
  echo -e "${GREEN}Services running:${NC}"
  echo "  Private Lab: http://localhost:4567 (PID: $PRIVATE_PID)"
  echo "  Public Portal: http://localhost:8080 (PID: $PUBLIC_PID)"
  echo ""
  echo -e "${YELLOW}To stop:${NC}"
  echo "  kill $PRIVATE_PID $PUBLIC_PID"
fi

echo ""
echo -e "${BLUE}Setup complete! Happy testing! 🔒📱${NC}"
echo ""

create_systemd_services() {
  echo -e "${GREEN}[*]${NC} Creating systemd service files..."

  # Private lab service
  sudo tee /etc/systemd/system/mobile-lab-private.service > /dev/null <<EOF
[Unit]
Description=Mobile Security Lab - Private Interface
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)/web_gui
ExecStart=/usr/bin/ruby mobile_lab_server.rb
Restart=on-failure
Environment="LAB_PASSWORD=change_me"

[Install]
WantedBy=multi-user.target
EOF

  # Public portal service
  sudo tee /etc/systemd/system/mobile-lab-public.service > /dev/null <<EOF
[Unit]
Description=Mobile Security Lab - Public Portal
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)/web_gui
ExecStart=/usr/bin/ruby public_portal.rb
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

  sudo systemctl daemon-reload

  echo -e "${GREEN}[+]${NC} Systemd services created"
  echo ""
  echo "Enable and start with:"
  echo "  sudo systemctl enable mobile-lab-private"
  echo "  sudo systemctl start mobile-lab-private"
  echo "  sudo systemctl enable mobile-lab-public"
  echo "  sudo systemctl start mobile-lab-public"
}
