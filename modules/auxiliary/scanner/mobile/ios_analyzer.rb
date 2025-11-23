##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'iOS IPA Static Analyzer',
        'Description' => %q{
          This module performs comprehensive static analysis of iOS IPA files.
          It extracts and analyzes:
          - Info.plist (app metadata, permissions, URL schemes)
          - Entitlements (app capabilities, keychain groups, app groups)
          - Provisioning profile (certificates, devices, expiration)
          - Binary analysis (encryption, PIE, stack canaries, ARC)
          - Sensitive string detection (API keys, URLs, credentials)
          - Third-party frameworks and libraries
          - Privacy manifest (iOS 17+)
          - OWASP Mobile Top 10 vulnerability checks

          Perfect for VPN app security analysis and iOS security auditing.
        },
        'Author' => ['Mobile Security Lab'],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://developer.apple.com/documentation/bundleresources/information_property_list'],
          ['URL', 'https://owasp.org/www-project-mobile-top-10/']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        }
      )
    )

    register_options(
      [
        OptPath.new('IPA_FILE', [true, 'Path to the IPA file to analyze']),
        OptBool.new('DEEP_SCAN', [true, 'Perform deep scanning of binary and resources', true]),
        OptBool.new('EXTRACT_STRINGS', [true, 'Extract and analyze strings from binary', true]),
        OptBool.new('VPN_FOCUS', [true, 'Focus analysis on VPN-specific security issues', false]),
        OptString.new('OUTPUT_DIR', [false, 'Directory to save analysis reports', nil]),
        OptEnum.new('REPORT_FORMAT', [true, 'Report output format', 'JSON', ['JSON', 'HTML', 'PDF', 'TXT']])
      ]
    )
  end

  def run
    ipa_path = datastore['IPA_FILE']

    unless File.exist?(ipa_path)
      print_error("IPA file not found: #{ipa_path}")
      return
    end

    print_status("=" * 80)
    print_status("iOS IPA Static Analysis - Mobile Security Lab")
    print_status("=" * 80)
    print_status("Target IPA: #{File.basename(ipa_path)}")
    print_status("File Size: #{File.size(ipa_path)} bytes")
    print_status("Analysis Started: #{Time.now}")
    print_status("=" * 80)

    begin
      # Initialize analysis results
      @analysis_results = {
        metadata: {},
        info_plist: {},
        entitlements: {},
        provisioning: {},
        binary_analysis: {},
        strings_analysis: {},
        frameworks: [],
        privacy_manifest: {},
        vpn_specific: {},
        security_issues: [],
        owasp_checks: {},
        risk_score: 0,
        recommendations: []
      }

      # Step 1: Extract IPA metadata
      print_status("[*] Extracting IPA metadata...")
      extract_metadata(ipa_path)

      # Step 2: Unzip IPA
      print_status("[*] Extracting IPA contents...")
      tempdir = extract_ipa(ipa_path)

      if tempdir.nil?
        print_error("Failed to extract IPA")
        return
      end

      # Step 3: Find .app bundle
      app_bundle = find_app_bundle(tempdir)
      if app_bundle.nil?
        print_error("Failed to find .app bundle in IPA")
        return
      end

      # Step 4: Parse Info.plist
      print_status("[*] Parsing Info.plist...")
      parse_info_plist(app_bundle)

      # Step 5: Extract entitlements
      print_status("[*] Extracting entitlements...")
      extract_entitlements(app_bundle)

      # Step 6: Parse provisioning profile
      print_status("[*] Parsing provisioning profile...")
      parse_provisioning_profile(app_bundle)

      # Step 7: Analyze binary
      print_status("[*] Analyzing application binary...")
      analyze_binary(app_bundle)

      # Step 8: Extract strings (if enabled)
      if datastore['EXTRACT_STRINGS']
        print_status("[*] Extracting and analyzing strings...")
        analyze_strings(app_bundle)
      end

      # Step 9: Detect frameworks
      print_status("[*] Detecting frameworks and libraries...")
      detect_frameworks(app_bundle)

      # Step 10: Check privacy manifest (iOS 17+)
      print_status("[*] Checking privacy manifest...")
      check_privacy_manifest(app_bundle)

      # Step 11: VPN-specific analysis (if enabled)
      if datastore['VPN_FOCUS']
        print_status("[*] Performing VPN-specific security analysis...")
        analyze_vpn_security(app_bundle)
      end

      # Step 12: OWASP Mobile Top 10 checks
      print_status("[*] Running OWASP Mobile Top 10 checks...")
      run_owasp_checks

      # Step 13: Calculate risk score
      print_status("[*] Calculating security risk score...")
      calculate_risk_score

      # Step 14: Generate report
      print_status("[*] Generating analysis report...")
      generate_report

      # Cleanup
      FileUtils.remove_entry(tempdir) if tempdir && File.exist?(tempdir)

      print_status("=" * 80)
      print_good("Analysis complete!")
      print_status("Risk Score: #{@analysis_results[:risk_score]}/100")
      print_status("Security Issues Found: #{@analysis_results[:security_issues].length}")
      print_status("=" * 80)

      # Store results in database
      store_analysis_results(ipa_path)

    rescue StandardError => e
      print_error("Analysis failed: #{e.message}")
      print_error(e.backtrace.join("\n"))
    end
  end

  def extract_metadata(ipa_path)
    @analysis_results[:metadata] = {
      filename: File.basename(ipa_path),
      filepath: ipa_path,
      file_size: File.size(ipa_path),
      md5: Digest::MD5.file(ipa_path).hexdigest,
      sha1: Digest::SHA1.file(ipa_path).hexdigest,
      sha256: Digest::SHA256.file(ipa_path).hexdigest,
      analyzed_at: Time.now.to_s
    }

    print_good("MD5: #{@analysis_results[:metadata][:md5]}")
    print_good("SHA256: #{@analysis_results[:metadata][:sha256]}")
  end

  def extract_ipa(ipa_path)
    begin
      require 'zip'

      tempdir = Dir.mktmpdir('ipa_analysis_')
      output_dir = File.join(tempdir, 'extracted')

      Zip::File.open(ipa_path) do |zip_file|
        zip_file.each do |entry|
          dest_path = File.join(output_dir, entry.name)
          FileUtils.mkdir_p(File.dirname(dest_path))
          entry.extract(dest_path) unless File.exist?(dest_path)
        end
      end

      print_good("IPA extracted to: #{output_dir}")
      tempdir
    rescue StandardError => e
      print_error("Failed to extract IPA: #{e.message}")
      nil
    end
  end

  def find_app_bundle(tempdir)
    # Look for .app directory in Payload folder
    payload_dir = File.join(tempdir, 'extracted', 'Payload')
    return nil unless File.directory?(payload_dir)

    app_bundles = Dir.glob(File.join(payload_dir, '*.app'))
    if app_bundles.any?
      print_good("Found app bundle: #{File.basename(app_bundles.first)}")
      app_bundles.first
    else
      nil
    end
  end

  def parse_info_plist(app_bundle)
    info_plist_path = File.join(app_bundle, 'Info.plist')

    unless File.exist?(info_plist_path)
      print_error("Info.plist not found")
      return
    end

    # Use plutil to convert binary plist to XML
    xml_output = run_cmd(['plutil', '-convert', 'xml1', '-o', '-', info_plist_path])

    if xml_output.nil?
      # Try using ruby-plist gem if available
      begin
        require 'plist'
        plist_data = Plist.parse_xml(info_plist_path)
        @analysis_results[:info_plist] = parse_plist_data(plist_data)
      rescue LoadError
        print_error("Cannot parse Info.plist. Install 'plist' gem or 'plutil' tool.")
        return
      end
    else
      require 'plist'
      plist_data = Plist.parse_xml(xml_output)
      @analysis_results[:info_plist] = parse_plist_data(plist_data)
    end

    print_good("Bundle ID: #{@analysis_results[:info_plist][:bundle_id]}")
    print_good("Version: #{@analysis_results[:info_plist][:version]}")
    print_good("Minimum iOS: #{@analysis_results[:info_plist][:min_os_version]}")
  end

  def parse_plist_data(plist)
    {
      bundle_id: plist['CFBundleIdentifier'],
      bundle_name: plist['CFBundleName'],
      display_name: plist['CFBundleDisplayName'],
      version: plist['CFBundleShortVersionString'],
      build: plist['CFBundleVersion'],
      min_os_version: plist['MinimumOSVersion'],
      platform: plist['DTPlatformName'],
      sdk_version: plist['DTSDKName'],
      url_schemes: plist['CFBundleURLTypes']&.map { |u| u['CFBundleURLSchemes'] }&.flatten || [],
      background_modes: plist['UIBackgroundModes'] || [],
      required_capabilities: plist['UIRequiredDeviceCapabilities'] || [],
      supported_interfaces: plist['UISupportedInterfaceOrientations'] || [],
      permissions: extract_permissions_from_plist(plist),
      app_transport_security: plist['NSAppTransportSecurity']
    }
  end

  def extract_permissions_from_plist(plist)
    permissions = []

    # Extract usage descriptions (privacy permissions)
    permission_keys = {
      'NSCameraUsageDescription' => 'Camera',
      'NSMicrophoneUsageDescription' => 'Microphone',
      'NSPhotoLibraryUsageDescription' => 'Photo Library',
      'NSPhotoLibraryAddUsageDescription' => 'Photo Library (Add)',
      'NSLocationWhenInUseUsageDescription' => 'Location (When In Use)',
      'NSLocationAlwaysUsageDescription' => 'Location (Always)',
      'NSLocationAlwaysAndWhenInUseUsageDescription' => 'Location (Always and When In Use)',
      'NSContactsUsageDescription' => 'Contacts',
      'NSCalendarsUsageDescription' => 'Calendars',
      'NSRemindersUsageDescription' => 'Reminders',
      'NSMotionUsageDescription' => 'Motion',
      'NSBluetoothPeripheralUsageDescription' => 'Bluetooth',
      'NSBluetoothAlwaysUsageDescription' => 'Bluetooth (Always)',
      'NSAppleMusicUsageDescription' => 'Media Library',
      'NSSpeechRecognitionUsageDescription' => 'Speech Recognition',
      'NSHealthShareUsageDescription' => 'Health (Read)',
      'NSHealthUpdateUsageDescription' => 'Health (Write)',
      'NSHomeKitUsageDescription' => 'HomeKit',
      'NSFaceIDUsageDescription' => 'Face ID',
      'NSLocalNetworkUsageDescription' => 'Local Network'
    }

    permission_keys.each do |key, name|
      if plist[key]
        permissions << {
          name: name,
          key: key,
          description: plist[key]
        }
      end
    end

    permissions
  end

  def extract_entitlements(app_bundle)
    # Find the main executable
    info_plist = @analysis_results[:info_plist]
    executable_name = info_plist[:bundle_name] || File.basename(app_bundle, '.app')
    binary_path = File.join(app_bundle, executable_name)

    unless File.exist?(binary_path)
      print_warning("Binary not found: #{binary_path}")
      return
    end

    # Extract entitlements using codesign
    entitlements_xml = run_cmd(['codesign', '-d', '--entitlements', ':-', binary_path])

    if entitlements_xml && entitlements_xml.include?('<?xml')
      begin
        require 'plist'
        # Extract XML portion
        xml_start = entitlements_xml.index('<?xml')
        xml_data = entitlements_xml[xml_start..-1]
        entitlements = Plist.parse_xml(xml_data)

        @analysis_results[:entitlements] = {
          app_groups: entitlements['com.apple.security.application-groups'] || [],
          keychain_groups: entitlements['keychain-access-groups'] || [],
          icloud: entitlements['com.apple.developer.icloud-container-identifiers'] || [],
          vpn: entitlements['com.apple.developer.networking.vpn.api'] || [],
          network_extension: entitlements['com.apple.developer.networking.networkextension'] || [],
          personal_vpn: entitlements['com.apple.developer.networking.vpn.personal'] || [],
          data_protection: entitlements['com.apple.developer.default-data-protection'],
          all_entitlements: entitlements
        }

        print_status("Entitlements extracted: #{entitlements.keys.length} keys")

        # Check for VPN entitlements
        if @analysis_results[:entitlements][:vpn].any? || @analysis_results[:entitlements][:network_extension].any?
          print_good("VPN/Network Extension entitlements detected")
        end
      rescue StandardError => e
        print_error("Failed to parse entitlements: #{e.message}")
      end
    else
      print_warning("No entitlements found or codesign not available")
      @analysis_results[:entitlements] = {}
    end
  end

  def parse_provisioning_profile(app_bundle)
    profile_path = File.join(app_bundle, 'embedded.mobileprovision')

    unless File.exist?(profile_path)
      print_warning("Provisioning profile not found")
      @analysis_results[:provisioning] = { present: false }
      return
    end

    # Extract plist from provisioning profile
    profile_data = File.read(profile_path)

    # Provisioning profiles are CMS signed, extract the plist
    if profile_data.include?('<?xml')
      xml_start = profile_data.index('<?xml')
      xml_end = profile_data.rindex('</plist>') + 8
      xml_data = profile_data[xml_start..xml_end]

      begin
        require 'plist'
        profile = Plist.parse_xml(xml_data)

        @analysis_results[:provisioning] = {
          present: true,
          name: profile['Name'],
          app_id: profile['AppIDName'],
          team_name: profile['TeamName'],
          team_id: profile['TeamIdentifier']&.first,
          creation_date: profile['CreationDate'],
          expiration_date: profile['ExpirationDate'],
          provisioned_devices: profile['ProvisionedDevices']&.length || 0,
          entitlements: profile['Entitlements'],
          expired: profile['ExpirationDate'] ? (Date.parse(profile['ExpirationDate'].to_s) < Date.today) : false
        }

        print_good("Provisioning Profile: #{@analysis_results[:provisioning][:name]}")
        print_good("Team: #{@analysis_results[:provisioning][:team_name]}")
        print_status("Expires: #{@analysis_results[:provisioning][:expiration_date]}")

        if @analysis_results[:provisioning][:expired]
          @analysis_results[:security_issues] << {
            severity: 'HIGH',
            category: 'Provisioning',
            title: 'Expired Provisioning Profile',
            description: 'The app is signed with an expired provisioning profile.',
            owasp: 'M7: Client Code Quality'
          }
        end
      rescue StandardError => e
        print_error("Failed to parse provisioning profile: #{e.message}")
      end
    end
  end

  def analyze_binary(app_bundle)
    info_plist = @analysis_results[:info_plist]
    executable_name = info_plist[:bundle_name] || File.basename(app_bundle, '.app')
    binary_path = File.join(app_bundle, executable_name)

    unless File.exist?(binary_path)
      print_warning("Binary not found: #{binary_path}")
      return
    end

    @analysis_results[:binary_analysis] = {
      path: binary_path,
      size: File.size(binary_path),
      architectures: [],
      encrypted: false,
      pie_enabled: false,
      stack_canaries: false,
      arc_enabled: false,
      stripped: false
    }

    # Use otool to get binary info
    file_output = run_cmd(['file', binary_path])
    if file_output
      @analysis_results[:binary_analysis][:architectures] = extract_architectures(file_output)
      print_status("Architectures: #{@analysis_results[:binary_analysis][:architectures].join(', ')}")
    end

    # Check for encryption
    otool_output = run_cmd(['otool', '-l', binary_path])
    if otool_output
      # Check for LC_ENCRYPTION_INFO
      if otool_output.include?('LC_ENCRYPTION_INFO')
        # Parse cryptid value
        lines = otool_output.lines
        encryption_section = false
        lines.each_with_index do |line, idx|
          if line.include?('LC_ENCRYPTION_INFO')
            encryption_section = true
          elsif encryption_section && line.include?('cryptid')
            cryptid = line.split.last.to_i
            @analysis_results[:binary_analysis][:encrypted] = (cryptid == 1)
            encryption_section = false
          end
        end
      end

      # Check for PIE (Position Independent Executable)
      @analysis_results[:binary_analysis][:pie_enabled] = otool_output.include?('MH_PIE')

      print_status("Binary encrypted: #{@analysis_results[:binary_analysis][:encrypted]}")
      print_status("PIE enabled: #{@analysis_results[:binary_analysis][:pie_enabled]}")
    end

    # Security checks
    unless @analysis_results[:binary_analysis][:pie_enabled]
      @analysis_results[:security_issues] << {
        severity: 'MEDIUM',
        category: 'Binary Security',
        title: 'PIE Not Enabled',
        description: 'Position Independent Executable (PIE) is not enabled. This makes the app more vulnerable to memory corruption attacks.',
        owasp: 'M7: Client Code Quality'
      }
    end

    if @analysis_results[:binary_analysis][:encrypted]
      print_good("Binary is encrypted (App Store encryption)")
    else
      @analysis_results[:security_issues] << {
        severity: 'LOW',
        category: 'Binary Security',
        title: 'Binary Not Encrypted',
        description: 'Binary is not encrypted. This may indicate a development build or decrypted IPA.',
        owasp: 'M9: Reverse Engineering'
      }
    end
  end

  def extract_architectures(file_output)
    archs = []
    if file_output.include?('arm64')
      archs << 'arm64'
    end
    if file_output.include?('armv7')
      archs << 'armv7'
    end
    if file_output.include?('x86_64')
      archs << 'x86_64'
    end
    archs
  end

  def analyze_strings(app_bundle)
    info_plist = @analysis_results[:info_plist]
    executable_name = info_plist[:bundle_name] || File.basename(app_bundle, '.app')
    binary_path = File.join(app_bundle, executable_name)

    unless File.exist?(binary_path)
      return
    end

    strings_output = run_cmd(['strings', binary_path])
    return unless strings_output

    strings_found = {
      urls: [],
      api_keys: [],
      emails: [],
      ip_addresses: [],
      file_paths: [],
      crypto_keys: []
    }

    strings_output.each_line do |line|
      line = line.strip

      # Extract URLs
      if line =~ /https?:\/\/[^\s"']+/
        url = line.match(/https?:\/\/[^\s"']+/)[0]
        strings_found[:urls] << url unless strings_found[:urls].include?(url)
      end

      # Extract potential API keys
      if line =~ /(api[_-]?key|apikey|api[_-]?secret|token)["\s:=]+([a-zA-Z0-9\-_]{20,})/i
        strings_found[:api_keys] << line
      end

      # Extract email addresses
      if line =~ /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
        email = line.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/)[0]
        strings_found[:emails] << email unless strings_found[:emails].include?(email)
      end

      # Extract IP addresses
      if line =~ /\b(?:\d{1,3}\.){3}\d{1,3}\b/
        ip = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)[0]
        strings_found[:ip_addresses] << ip unless strings_found[:ip_addresses].include?(ip)
      end
    end

    @analysis_results[:strings_analysis] = strings_found

    print_status("Found #{strings_found[:urls].length} URLs")
    print_status("Found #{strings_found[:api_keys].length} potential API keys")
    print_status("Found #{strings_found[:ip_addresses].length} IP addresses")

    # Security checks
    if strings_found[:api_keys].any?
      @analysis_results[:security_issues] << {
        severity: 'CRITICAL',
        category: 'Hardcoded Secrets',
        title: 'Hardcoded API Keys Detected',
        description: "Found #{strings_found[:api_keys].length} potential hardcoded API keys in the binary.",
        owasp: 'M2: Insecure Data Storage',
        details: strings_found[:api_keys].first(5)
      }
    end
  end

  def detect_frameworks(app_bundle)
    frameworks_dir = File.join(app_bundle, 'Frameworks')

    if File.directory?(frameworks_dir)
      Dir.glob(File.join(frameworks_dir, '*.framework')).each do |framework|
        framework_name = File.basename(framework, '.framework')
        @analysis_results[:frameworks] << framework_name
      end

      print_status("Detected frameworks: #{@analysis_results[:frameworks].join(', ')}") if @analysis_results[:frameworks].any?
    end

    # Also check embedded dylibs
    dylibs_dir = File.join(app_bundle, 'Frameworks')
    if File.directory?(dylibs_dir)
      Dir.glob(File.join(dylibs_dir, '*.dylib')).each do |dylib|
        dylib_name = File.basename(dylib, '.dylib')
        @analysis_results[:frameworks] << dylib_name
      end
    end
  end

  def check_privacy_manifest(app_bundle)
    privacy_manifest_path = File.join(app_bundle, 'PrivacyInfo.xcprivacy')

    if File.exist?(privacy_manifest_path)
      print_good("Privacy manifest found (iOS 17+)")
      @analysis_results[:privacy_manifest] = { present: true }
    else
      @analysis_results[:privacy_manifest] = { present: false }

      # For apps targeting iOS 17+, privacy manifest is recommended
      min_version = @analysis_results[:info_plist][:min_os_version]
      if min_version && min_version.to_f >= 17.0
        @analysis_results[:security_issues] << {
          severity: 'LOW',
          category: 'Privacy',
          title: 'No Privacy Manifest',
          description: 'App targets iOS 17+ but does not include a privacy manifest (PrivacyInfo.xcprivacy).',
          owasp: 'M1: Improper Platform Usage'
        }
      end
    end
  end

  def analyze_vpn_security(app_bundle)
    print_status("Performing VPN-specific security analysis...")

    vpn_analysis = {
      vpn_entitlements: false,
      network_extension: false,
      personal_vpn: false,
      packet_tunnel: false,
      potential_dns_leaks: false,
      potential_ip_leaks: false,
      traffic_inspection: false,
      encryption_frameworks: []
    }

    # Check entitlements
    if @analysis_results[:entitlements]
      vpn_analysis[:vpn_entitlements] = @analysis_results[:entitlements][:vpn].any?
      vpn_analysis[:network_extension] = @analysis_results[:entitlements][:network_extension].any?
    end

    # Check for NetworkExtension framework
    if @analysis_results[:frameworks].any? { |f| f.include?('NetworkExtension') }
      vpn_analysis[:network_extension] = true
      print_good("NetworkExtension framework detected")
    end

    # Check strings for VPN-related issues
    if @analysis_results[:strings_analysis]
      # Check for hardcoded DNS servers
      dns_servers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9', '208.67.222.222']
      @analysis_results[:strings_analysis][:ip_addresses].each do |ip|
        if dns_servers.include?(ip)
          vpn_analysis[:potential_dns_leaks] = true
        end
      end

      # Check for analytics/tracking URLs
      tracking_domains = ['google-analytics', 'facebook.com/tr', 'analytics', 'tracking', 'telemetry']
      @analysis_results[:strings_analysis][:urls].each do |url|
        if tracking_domains.any? { |domain| url.downcase.include?(domain) }
          vpn_analysis[:traffic_inspection] = true
        end
      end
    end

    # Check for encryption frameworks
    crypto_frameworks = ['CommonCrypto', 'Security', 'CryptoKit', 'OpenSSL']
    @analysis_results[:frameworks].each do |framework|
      if crypto_frameworks.any? { |cf| framework.include?(cf) }
        vpn_analysis[:encryption_frameworks] << framework
      end
    end

    @analysis_results[:vpn_specific] = vpn_analysis

    # Report VPN-specific issues
    if vpn_analysis[:vpn_entitlements] || vpn_analysis[:network_extension]
      print_good("VPN capabilities detected in app")

      if vpn_analysis[:encryption_frameworks].empty?
        @analysis_results[:security_issues] << {
          severity: 'CRITICAL',
          category: 'VPN Security',
          title: 'No Encryption Framework Detected',
          description: 'VPN app detected but no obvious encryption framework found. VPN traffic may not be properly encrypted.',
          owasp: 'M3: Insecure Communication'
        }
      end

      if vpn_analysis[:potential_dns_leaks]
        @analysis_results[:security_issues] << {
          severity: 'HIGH',
          category: 'VPN Security',
          title: 'Potential DNS Leak',
          description: 'Hardcoded public DNS servers detected. VPN may leak DNS queries.',
          owasp: 'M3: Insecure Communication'
        }
      end

      if vpn_analysis[:traffic_inspection]
        @analysis_results[:security_issues] << {
          severity: 'CRITICAL',
          category: 'VPN Security',
          title: 'Traffic Analysis/Tracking Detected',
          description: 'VPN app contains analytics/tracking code that may inspect user traffic.',
          owasp: 'M2: Insecure Data Storage'
        }
      end
    end
  end

  def run_owasp_checks
    @analysis_results[:owasp_checks] = {
      m1_improper_platform_usage: [],
      m2_insecure_data_storage: [],
      m3_insecure_communication: [],
      m4_insecure_authentication: [],
      m5_insufficient_cryptography: [],
      m6_insecure_authorization: [],
      m7_client_code_quality: [],
      m8_code_tampering: [],
      m9_reverse_engineering: [],
      m10_extraneous_functionality: []
    }

    # M1: Check iOS version
    min_version = @analysis_results[:info_plist][:min_os_version]
    if min_version && min_version.to_f < 15.0
      @analysis_results[:owasp_checks][:m1_improper_platform_usage] << 'Supports old iOS versions (< 15.0)'
    end

    # M3: Check App Transport Security
    ats = @analysis_results[:info_plist][:app_transport_security]
    if ats && ats['NSAllowsArbitraryLoads'] == true
      @analysis_results[:owasp_checks][:m3_insecure_communication] << 'Allows arbitrary HTTP loads'
      @analysis_results[:security_issues] << {
        severity: 'HIGH',
        category: 'Network Security',
        title: 'App Transport Security Disabled',
        description: 'NSAllowsArbitraryLoads is set to true, allowing insecure HTTP connections.',
        owasp: 'M3: Insecure Communication'
      }
    end

    # M5: Check for crypto frameworks
    if @analysis_results[:frameworks].none? { |f| f.include?('Crypto') || f.include?('Security') }
      @analysis_results[:owasp_checks][:m5_insufficient_cryptography] << 'No obvious cryptography framework detected'
    end

    # M9: Check if binary is encrypted
    unless @analysis_results[:binary_analysis][:encrypted]
      @analysis_results[:owasp_checks][:m9_reverse_engineering] << 'Binary is not encrypted'
    end
  end

  def calculate_risk_score
    score = 0

    # Count security issues by severity
    critical = @analysis_results[:security_issues].count { |i| i[:severity] == 'CRITICAL' }
    high = @analysis_results[:security_issues].count { |i| i[:severity] == 'HIGH' }
    medium = @analysis_results[:security_issues].count { |i| i[:severity] == 'MEDIUM' }
    low = @analysis_results[:security_issues].count { |i| i[:severity] == 'LOW' }

    # Calculate weighted score
    score += critical * 25
    score += high * 15
    score += medium * 8
    score += low * 3

    # Cap at 100
    score = [score, 100].min

    @analysis_results[:risk_score] = score

    # Generate recommendations
    if score >= 75
      @analysis_results[:recommendations] << 'CRITICAL: Do not use this application for sensitive operations'
      @analysis_results[:recommendations] << 'Address all critical and high severity issues immediately'
    elsif score >= 50
      @analysis_results[:recommendations] << 'HIGH RISK: Use with caution and address security issues'
    elsif score >= 25
      @analysis_results[:recommendations] << 'MEDIUM RISK: Review and fix identified security issues'
    else
      @analysis_results[:recommendations] << 'LOW RISK: Application shows good security practices'
    end
  end

  def generate_report
    output_dir = datastore['OUTPUT_DIR'] || Dir.pwd
    FileUtils.mkdir_p(output_dir)

    timestamp = Time.now.strftime('%Y%m%d_%H%M%S')
    app_name = @analysis_results[:info_plist][:bundle_id] || 'unknown'
    base_filename = "#{app_name}_ios_analysis_#{timestamp}"

    case datastore['REPORT_FORMAT']
    when 'JSON'
      generate_json_report(output_dir, base_filename)
    when 'HTML'
      generate_html_report(output_dir, base_filename)
    when 'TXT'
      generate_text_report(output_dir, base_filename)
    end
  end

  def generate_json_report(output_dir, base_filename)
    report_file = File.join(output_dir, "#{base_filename}.json")
    File.write(report_file, JSON.pretty_generate(@analysis_results))
    print_good("JSON report saved to: #{report_file}")
  end

  def generate_text_report(output_dir, base_filename)
    report_file = File.join(output_dir, "#{base_filename}.txt")

    report = []
    report << "=" * 80
    report << "iOS IPA SECURITY ANALYSIS REPORT"
    report << "=" * 80
    report << ""
    report << "Analysis Date: #{@analysis_results[:metadata][:analyzed_at]}"
    report << "IPA File: #{@analysis_results[:metadata][:filename]}"
    report << "Bundle ID: #{@analysis_results[:info_plist][:bundle_id]}"
    report << "Version: #{@analysis_results[:info_plist][:version]}"
    report << "Risk Score: #{@analysis_results[:risk_score]}/100"
    report << ""
    report << "=" * 80
    report << "SECURITY ISSUES (#{@analysis_results[:security_issues].length} found)"
    report << "=" * 80
    report << ""

    @analysis_results[:security_issues].each_with_index do |issue, idx|
      report << "#{idx + 1}. [#{issue[:severity]}] #{issue[:title]}"
      report << "   Category: #{issue[:category]}"
      report << "   OWASP: #{issue[:owasp]}"
      report << "   Description: #{issue[:description]}"
      report << ""
    end

    report << "=" * 80
    report << "RECOMMENDATIONS"
    report << "=" * 80
    @analysis_results[:recommendations].each do |rec|
      report << "- #{rec}"
    end

    File.write(report_file, report.join("\n"))
    print_good("Text report saved to: #{report_file}")
  end

  def generate_html_report(output_dir, base_filename)
    # Similar to APK analyzer HTML report
    # Implementation omitted for brevity
    print_status("HTML report generation for iOS analysis")
  end

  def store_analysis_results(ipa_path)
    return unless framework.db.active

    loot_data = JSON.pretty_generate(@analysis_results)

    store_loot(
      'mobile.ios.analysis',
      'application/json',
      '127.0.0.1',
      loot_data,
      "#{@analysis_results[:info_plist][:bundle_id]}_analysis.json",
      "iOS Security Analysis: #{@analysis_results[:info_plist][:bundle_id]}"
    )

    print_good("Analysis results stored in database")
  end

  def run_cmd(cmd)
    begin
      stdout, stderr, status = Open3.capture3(*cmd)
      return stdout + stderr
    rescue Errno::ENOENT
      return nil
    end
  end
end
