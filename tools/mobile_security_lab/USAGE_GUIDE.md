# Mobile Security Lab - Usage Guide

## Table of Contents
1. [Getting Started](#getting-started)
2. [Static Analysis](#static-analysis)
3. [Dynamic Analysis](#dynamic-analysis)
4. [VPN Security Testing](#vpn-security-testing)
5. [Web Interface](#web-interface)
6. [Batch Processing](#batch-processing)
7. [Integration](#integration)
8. [Best Practices](#best-practices)

## Getting Started

### Quick Start Checklist
- [ ] Run setup.sh
- [ ] Connect Android/iOS device (for dynamic analysis)
- [ ] Set LAB_PASSWORD environment variable
- [ ] Start web interfaces
- [ ] Download sample VPN apps

### Environment Setup
```bash
export LAB_PASSWORD="your_secure_password_here"
export MOBSF_API_KEY="your_mobsf_api_key"  # Optional
```

## Static Analysis

### Android APK Analysis

#### Basic Analysis
```bash
msfconsole -q -x "
  use auxiliary/scanner/mobile/apk_analyzer;
  set APK_FILE /path/to/app.apk;
  set DEEP_SCAN true;
  set EXTRACT_STRINGS true;
  set REPORT_FORMAT HTML;
  set OUTPUT_DIR ./reports;
  run;
  exit
"
```

#### VPN-Focused Analysis
```bash
msfconsole -q -x "
  use auxiliary/scanner/mobile/apk_analyzer;
  set APK_FILE /path/to/vpn.apk;
  set VPN_FOCUS true;
  run;
  exit
"
```

### iOS IPA Analysis

```bash
msfconsole -q -x "
  use auxiliary/scanner/mobile/ios_analyzer;
  set IPA_FILE /path/to/app.ipa;
  set DEEP_SCAN true;
  set VPN_FOCUS true;
  set REPORT_FORMAT HTML;
  run;
  exit
"
```

## Dynamic Analysis

### Prerequisites
- Android device with USB debugging enabled OR
- iOS device (jailbroken for full features)
- ADB/libimobiledevice installed
- Device connected via USB

### Android Dynamic Analysis

#### Connect Device
```bash
# Enable USB debugging on device
# Settings > Developer Options > USB Debugging

# Verify connection
adb devices

# Should show:
# List of devices attached
# DEVICE_ID    device
```

#### Run Analysis
```bash
msfconsole -q -x "
  use auxiliary/scanner/mobile/dynamic_analyzer;
  set APP_FILE /path/to/app.apk;
  set PLATFORM android;
  set DEVICE_ID YOUR_DEVICE_ID;
  set INSTALL_APP true;
  set CAPTURE_TRAFFIC true;
  set FRIDA_HOOK true;
  set RUNTIME_DURATION 600;
  set RECORD_SCREEN true;
  run;
  exit
"
```

### iOS Dynamic Analysis

```bash
# Check connected iOS devices
idevice_id -l

# Run analysis
msfconsole -q -x "
  use auxiliary/scanner/mobile/dynamic_analyzer;
  set APP_FILE /path/to/app.ipa;
  set PLATFORM ios;
  set DEVICE_ID YOUR_DEVICE_UDID;
  set INSTALL_APP true;
  set CAPTURE_TRAFFIC true;
  run;
  exit
"
```

## VPN Security Testing

### Comprehensive VPN Analysis

```bash
msfconsole -q -x "
  use auxiliary/scanner/mobile/vpn_analyzer;
  set APP_FILE /path/to/vpn.apk;
  set APP_TYPE APK;
  set DEEP_SCAN true;
  set PRIVACY_CHECK true;
  set REPORT_FORMAT HTML;
  run;
  exit
"
```

### Live VPN Leak Testing

```bash
# Requires connected device and VPN app installed

msfconsole -q -x "
  use auxiliary/scanner/mobile/dynamic_analyzer;
  set APP_FILE /path/to/vpn.apk;
  set PLATFORM android;
  set VPN_LEAK_TEST true;
  set CAPTURE_TRAFFIC true;
  set RUNTIME_DURATION 900;
  run;
  exit
"
```

### Batch VPN Analysis

```bash
#!/bin/bash
# analyze_all_vpns.sh

VPN_APPS_DIR="vpn_apps/us/android"

for vpn_dir in $VPN_APPS_DIR/*/; do
  for apk in $vpn_dir/*.apk; do
    echo "Analyzing: $apk"

    msfconsole -q -x "
      use auxiliary/scanner/mobile/vpn_analyzer;
      set APP_FILE $apk;
      set APP_TYPE APK;
      set OUTPUT_DIR ./vpn_reports;
      run;
      exit
    "

    sleep 5
  done
done

echo "Batch analysis complete!"
```

## Web Interface

### Starting Services

#### Private Lab
```bash
cd tools/mobile_security_lab/web_gui
LAB_PASSWORD="your_password" ruby mobile_lab_server.rb

# Or with environment file
cat > .env <<EOF
LAB_PASSWORD=your_secure_password
EOF

ruby mobile_lab_server.rb
```

#### Public Portal
```bash
cd tools/mobile_security_lab/web_gui
ruby public_portal.rb
```

### Web Interface Features

#### Upload and Analyze
1. Navigate to http://localhost:4567
2. Login with password
3. Click "New Analysis"
4. Upload APK/IPA
5. Select analysis type
6. Submit
7. Monitor progress
8. View results

#### API Usage

**Submit Analysis**
```bash
curl -X POST http://localhost:4567/api/v1/analyze \
  -u admin:your_password \
  -F "file=@app.apk" \
  -F "platform=android" \
  -F "analysis_type=vpn" \
  -F "vpn_focus=true"
```

**Check Status**
```bash
curl -X GET http://localhost:4567/api/v1/results/JOB_ID \
  -u admin:your_password
```

**Download Report**
```bash
curl -X GET http://localhost:4567/analyze/JOB_ID/download/html \
  -u admin:your_password \
  -o report.html
```

## Batch Processing

### Analyze All Apps in Directory

```bash
#!/bin/bash
# batch_analyze.sh

APP_DIR="/path/to/apps"
OUTPUT_DIR="./batch_reports"

mkdir -p $OUTPUT_DIR

for app in $APP_DIR/*.apk; do
  app_name=$(basename "$app" .apk)

  echo "Processing: $app_name"

  msfconsole -q -x "
    use auxiliary/scanner/mobile/apk_analyzer;
    set APK_FILE $app;
    set OUTPUT_DIR $OUTPUT_DIR/$app_name;
    set REPORT_FORMAT JSON;
    run;
    exit
  " > /dev/null 2>&1

  echo "  ✓ Complete"
done

echo ""
echo "Batch processing complete!"
echo "Reports saved to: $OUTPUT_DIR"
```

### Scheduled Analysis with Cron

```bash
# Add to crontab
# crontab -e

# Daily VPN app analysis at 2 AM
0 2 * * * /path/to/mobile_security_lab/scripts/daily_vpn_scan.sh

# Weekly comprehensive scan on Sundays at 3 AM
0 3 * * 0 /path/to/mobile_security_lab/scripts/weekly_full_scan.sh
```

## Integration

### MobSF Integration

```bash
# Start MobSF
cd Mobile-Security-Framework-MobSF
./run.sh &

# Run enhanced analysis
cd tools/mobile_security_lab
./mobsf_integration.rb \
  -f /path/to/vpn.apk \
  --enhanced \
  --api-key YOUR_API_KEY
```

### CI/CD Integration

**GitHub Actions Example**
```yaml
name: Mobile Security Scan

on:
  push:
    paths:
      - 'mobile-app/**'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Setup Mobile Security Lab
        run: |
          cd tools/mobile_security_lab
          ./setup.sh

      - name: Analyze APK
        run: |
          msfconsole -q -x "
            use auxiliary/scanner/mobile/apk_analyzer;
            set APK_FILE mobile-app/app-release.apk;
            set OUTPUT_DIR ./reports;
            run;
            exit
          "

      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: reports/
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any

    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    msfconsole -q -x "
                        use auxiliary/scanner/mobile/vpn_analyzer;
                        set APP_FILE ${WORKSPACE}/app.apk;
                        set OUTPUT_DIR ${WORKSPACE}/reports;
                        run;
                        exit
                    "
                '''
            }
        }

        stage('Publish Report') {
            steps {
                publishHTML([
                    reportName: 'Security Report',
                    reportDir: 'reports',
                    reportFiles: '*.html'
                ])
            }
        }
    }
}
```

## Best Practices

### Security
1. **Change default password** immediately
2. **Use HTTPS** in production (nginx reverse proxy)
3. **Restrict network access** with firewall rules
4. **Regular updates** of analysis tools
5. **Secure API keys** - never commit to git

### Performance
1. **Limit concurrent jobs** - Set max_concurrent_jobs in config
2. **Clean up old analyses** regularly
3. **Use SSD storage** for better I/O
4. **Allocate sufficient RAM** (minimum 8GB recommended)

### Analysis Quality
1. **Use DEEP_SCAN** for thorough analysis
2. **Enable VPN_FOCUS** for VPN apps
3. **Combine static + dynamic** for best results
4. **Compare multiple versions** of same app
5. **Verify findings** manually

### Reporting
1. **Generate multiple formats** (JSON for automation, HTML for humans)
2. **Archive reports** with version control
3. **Track findings over time**
4. **Share via public portal** when appropriate

## Troubleshooting

### Analysis Fails

**APK decompilation error**
```bash
# Update apktool
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.2.jar
# Replace old version
```

**Permission denied**
```bash
chmod +x tools/mobile_security_lab/*.rb
chmod +x tools/mobile_security_lab/*.sh
```

### Device Issues

**Device not detected**
```bash
# Android
adb kill-server
adb start-server
adb devices

# iOS
idevice_id -l
# Re-pair device if needed
```

**Frida not connecting**
```bash
# Install Frida server on device
adb push frida-server-VERSION-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c '/data/local/tmp/frida-server &'"
```

### Web Interface Issues

**Port already in use**
```bash
# Find and kill process
lsof -i :4567
kill PID

# Or change port
PORT=4568 ruby mobile_lab_server.rb
```

**Authentication fails**
```bash
# Check password is set
echo $LAB_PASSWORD

# Set if not
export LAB_PASSWORD="your_password"
```

## Advanced Usage

### Custom Analysis Modules

Create custom module in `modules/auxiliary/scanner/mobile/`:

```ruby
class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Custom Mobile Analyzer',
      'Description' => %q{Your custom analyzer},
      # ...
    ))
  end

  def run
    # Your analysis code
  end
end
```

### Extending Report Formats

Add custom report generators in analysis modules:

```ruby
def generate_custom_report(output_dir, base_filename)
  # Your custom report logic
end
```

### Integration with SIEM

Export findings to SIEM:

```bash
# Convert JSON to CEF format
./scripts/json_to_cef.rb \
  --input reports/analysis.json \
  --output siem/findings.cef

# Send to Splunk
curl -k https://splunk:8088/services/collector \
  -H "Authorization: Splunk YOUR_TOKEN" \
  -d @siem/findings.cef
```

---

**Need Help?** Check the [README](README.md) or open an issue on GitHub.
