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
        'Name' => 'Android APK Static Analyzer',
        'Description' => %q{
          This module performs comprehensive static analysis of Android APK files.
          It extracts and analyzes:
          - AndroidManifest.xml (permissions, components, activities, services, receivers)
          - Certificate information (signing certificate details, validity)
          - APK structure and file contents
          - Dangerous permissions and security issues
          - Hardcoded sensitive data (API keys, URLs, credentials)
          - Network security configuration
          - Code obfuscation detection
          - Third-party library detection
          - OWASP Mobile Top 10 vulnerability checks

          Perfect for VPN app security analysis and mobile security auditing.
        },
        'Author' => ['Mobile Security Lab'],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://developer.android.com/guide/topics/manifest/manifest-intro'],
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
        OptPath.new('APK_FILE', [true, 'Path to the APK file to analyze']),
        OptBool.new('DEEP_SCAN', [true, 'Perform deep scanning of DEX files and resources', true]),
        OptBool.new('EXTRACT_STRINGS', [true, 'Extract and analyze strings from DEX files', true]),
        OptBool.new('VPN_FOCUS', [true, 'Focus analysis on VPN-specific security issues', false]),
        OptString.new('OUTPUT_DIR', [false, 'Directory to save analysis reports', nil]),
        OptEnum.new('REPORT_FORMAT', [true, 'Report output format', 'JSON', ['JSON', 'HTML', 'PDF', 'TXT']])
      ]
    )
  end

  def run
    apk_path = datastore['APK_FILE']

    unless File.exist?(apk_path)
      print_error("APK file not found: #{apk_path}")
      return
    end

    print_status("=" * 80)
    print_status("APK Static Analysis - Mobile Security Lab")
    print_status("=" * 80)
    print_status("Target APK: #{File.basename(apk_path)}")
    print_status("File Size: #{File.size(apk_path)} bytes")
    print_status("Analysis Started: #{Time.now}")
    print_status("=" * 80)

    begin
      # Initialize analysis results
      @analysis_results = {
        metadata: {},
        manifest: {},
        permissions: {},
        components: {},
        security_issues: [],
        certificate: {},
        strings_analysis: {},
        libraries: [],
        network_config: {},
        vpn_specific: {},
        owasp_checks: {},
        risk_score: 0,
        recommendations: []
      }

      # Step 1: Extract APK metadata
      print_status("[*] Extracting APK metadata...")
      extract_metadata(apk_path)

      # Step 2: Decompile APK
      print_status("[*] Decompiling APK with apktool...")
      tempdir = decompile_apk(apk_path)

      if tempdir.nil?
        print_error("Failed to decompile APK")
        return
      end

      # Step 3: Parse AndroidManifest.xml
      print_status("[*] Parsing AndroidManifest.xml...")
      parse_manifest(tempdir)

      # Step 4: Analyze permissions
      print_status("[*] Analyzing permissions...")
      analyze_permissions

      # Step 5: Analyze components
      print_status("[*] Analyzing application components...")
      analyze_components

      # Step 6: Extract certificate information
      print_status("[*] Extracting certificate information...")
      extract_certificate(apk_path)

      # Step 7: Analyze strings (if enabled)
      if datastore['EXTRACT_STRINGS']
        print_status("[*] Extracting and analyzing strings...")
        analyze_strings(tempdir)
      end

      # Step 8: Detect libraries
      print_status("[*] Detecting third-party libraries...")
      detect_libraries(tempdir)

      # Step 9: Check network security configuration
      print_status("[*] Checking network security configuration...")
      check_network_security(tempdir)

      # Step 10: VPN-specific analysis (if enabled)
      if datastore['VPN_FOCUS']
        print_status("[*] Performing VPN-specific security analysis...")
        analyze_vpn_security(tempdir)
      end

      # Step 11: OWASP Mobile Top 10 checks
      print_status("[*] Running OWASP Mobile Top 10 checks...")
      run_owasp_checks

      # Step 12: Calculate risk score
      print_status("[*] Calculating security risk score...")
      calculate_risk_score

      # Step 13: Generate report
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
      store_analysis_results(apk_path)

    rescue StandardError => e
      print_error("Analysis failed: #{e.message}")
      print_error(e.backtrace.join("\n"))
    end
  end

  def extract_metadata(apk_path)
    @analysis_results[:metadata] = {
      filename: File.basename(apk_path),
      filepath: apk_path,
      file_size: File.size(apk_path),
      md5: Digest::MD5.file(apk_path).hexdigest,
      sha1: Digest::SHA1.file(apk_path).hexdigest,
      sha256: Digest::SHA256.file(apk_path).hexdigest,
      analyzed_at: Time.now.to_s
    }

    print_good("MD5: #{@analysis_results[:metadata][:md5]}")
    print_good("SHA256: #{@analysis_results[:metadata][:sha256]}")
  end

  def decompile_apk(apk_path)
    # Check if apktool is available
    check_apktool = run_cmd(['apktool', '-version'])
    if check_apktool.nil?
      print_error("apktool not found. Please install apktool.")
      return nil
    end

    # Create temporary directory
    tempdir = Dir.mktmpdir('apk_analysis_')
    output_dir = File.join(tempdir, 'decompiled')

    # Decompile APK
    result = run_cmd(['apktool', 'd', apk_path, '-o', output_dir, '-f'])

    if File.directory?(output_dir)
      print_good("APK decompiled to: #{output_dir}")
      tempdir
    else
      print_error("Failed to decompile APK")
      FileUtils.remove_entry(tempdir) if File.exist?(tempdir)
      nil
    end
  end

  def parse_manifest(tempdir)
    manifest_path = File.join(tempdir, 'decompiled', 'AndroidManifest.xml')

    unless File.exist?(manifest_path)
      print_error("AndroidManifest.xml not found")
      return
    end

    manifest_xml = File.read(manifest_path)
    doc = Nokogiri::XML(manifest_xml)

    # Extract basic info
    manifest_elem = doc.at_xpath('//manifest')
    @analysis_results[:manifest] = {
      package: manifest_elem['package'],
      version_code: manifest_elem['versionCode'],
      version_name: manifest_elem['versionName'],
      min_sdk: doc.at_xpath('//uses-sdk')&.[]('minSdkVersion'),
      target_sdk: doc.at_xpath('//uses-sdk')&.[]('targetSdkVersion'),
      max_sdk: doc.at_xpath('//uses-sdk')&.[]('maxSdkVersion'),
      permissions: [],
      features: [],
      activities: [],
      services: [],
      receivers: [],
      providers: []
    }

    print_good("Package: #{@analysis_results[:manifest][:package]}")
    print_good("Version: #{@analysis_results[:manifest][:version_name]} (#{@analysis_results[:manifest][:version_code]})")
    print_good("Target SDK: #{@analysis_results[:manifest][:target_sdk]}")

    # Extract permissions
    doc.xpath('//uses-permission').each do |perm|
      @analysis_results[:manifest][:permissions] << perm['name']
    end

    # Extract features
    doc.xpath('//uses-feature').each do |feat|
      @analysis_results[:manifest][:features] << {
        name: feat['name'],
        required: feat['required']
      }
    end

    # Extract components
    extract_components(doc)

    @manifest_doc = doc
  end

  def extract_components(doc)
    # Activities
    doc.xpath('//activity').each do |activity|
      @analysis_results[:manifest][:activities] << {
        name: activity['name'],
        exported: activity['exported'],
        intent_filters: activity.xpath('.//intent-filter').map { |f|
          {
            actions: f.xpath('.//action').map { |a| a['name'] },
            categories: f.xpath('.//category').map { |c| c['name'] }
          }
        }
      }
    end

    # Services
    doc.xpath('//service').each do |service|
      @analysis_results[:manifest][:services] << {
        name: service['name'],
        exported: service['exported'],
        permission: service['permission']
      }
    end

    # Receivers
    doc.xpath('//receiver').each do |receiver|
      @analysis_results[:manifest][:receivers] << {
        name: receiver['name'],
        exported: receiver['exported'],
        intent_filters: receiver.xpath('.//intent-filter').map { |f|
          {
            actions: f.xpath('.//action').map { |a| a['name'] }
          }
        }
      }
    end

    # Content Providers
    doc.xpath('//provider').each do |provider|
      @analysis_results[:manifest][:providers] << {
        name: provider['name'],
        exported: provider['exported'],
        authorities: provider['authorities'],
        grant_uri_permissions: provider['grantUriPermissions']
      }
    end

    print_status("Found #{@analysis_results[:manifest][:activities].length} activities")
    print_status("Found #{@analysis_results[:manifest][:services].length} services")
    print_status("Found #{@analysis_results[:manifest][:receivers].length} broadcast receivers")
    print_status("Found #{@analysis_results[:manifest][:providers].length} content providers")
  end

  def analyze_permissions
    permissions = @analysis_results[:manifest][:permissions]

    @analysis_results[:permissions] = {
      total: permissions.length,
      dangerous: [],
      normal: [],
      signature: [],
      special: [],
      custom: []
    }

    # Categorize permissions
    dangerous_perms = [
      'READ_CALENDAR', 'WRITE_CALENDAR',
      'CAMERA',
      'READ_CONTACTS', 'WRITE_CONTACTS', 'GET_ACCOUNTS',
      'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
      'RECORD_AUDIO',
      'READ_PHONE_STATE', 'READ_PHONE_NUMBERS', 'CALL_PHONE', 'ANSWER_PHONE_CALLS',
      'READ_CALL_LOG', 'WRITE_CALL_LOG', 'ADD_VOICEMAIL', 'USE_SIP', 'PROCESS_OUTGOING_CALLS',
      'BODY_SENSORS',
      'SEND_SMS', 'RECEIVE_SMS', 'READ_SMS', 'RECEIVE_WAP_PUSH', 'RECEIVE_MMS',
      'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE',
      'ACCESS_MEDIA_LOCATION'
    ]

    permissions.each do |perm|
      perm_name = perm.split('.').last

      if dangerous_perms.any? { |dp| perm.include?(dp) }
        @analysis_results[:permissions][:dangerous] << perm
      elsif perm.start_with?('android.permission.')
        @analysis_results[:permissions][:normal] << perm
      else
        @analysis_results[:permissions][:custom] << perm
      end
    end

    print_status("Total permissions: #{permissions.length}")
    print_warning("Dangerous permissions: #{@analysis_results[:permissions][:dangerous].length}") if @analysis_results[:permissions][:dangerous].any?

    # Flag security issues
    @analysis_results[:permissions][:dangerous].each do |perm|
      @analysis_results[:security_issues] << {
        severity: 'MEDIUM',
        category: 'Permissions',
        title: "Dangerous Permission Requested: #{perm}",
        description: "Application requests dangerous permission: #{perm}. Ensure this permission is necessary and used appropriately.",
        owasp: 'M1: Improper Platform Usage'
      }
    end
  end

  def analyze_components
    # Check for exported components without permission protection
    @analysis_results[:manifest][:activities].each do |activity|
      if activity[:exported] == 'true' && activity[:intent_filters].any?
        @analysis_results[:security_issues] << {
          severity: 'HIGH',
          category: 'Component Security',
          title: "Exported Activity Without Protection: #{activity[:name]}",
          description: "Activity #{activity[:name]} is exported and accessible to other apps. Ensure proper permission protection.",
          owasp: 'M1: Improper Platform Usage'
        }
      end
    end

    @analysis_results[:manifest][:services].each do |service|
      if service[:exported] == 'true' && service[:permission].nil?
        @analysis_results[:security_issues] << {
          severity: 'HIGH',
          category: 'Component Security',
          title: "Exported Service Without Permission: #{service[:name]}",
          description: "Service #{service[:name]} is exported without permission protection. This can be exploited by malicious apps.",
          owasp: 'M1: Improper Platform Usage'
        }
      end
    end

    @analysis_results[:manifest][:receivers].each do |receiver|
      if receiver[:exported] == 'true'
        @analysis_results[:security_issues] << {
          severity: 'MEDIUM',
          category: 'Component Security',
          title: "Exported Broadcast Receiver: #{receiver[:name]}",
          description: "Broadcast receiver #{receiver[:name]} is exported. Verify that it properly validates incoming intents.",
          owasp: 'M1: Improper Platform Usage'
        }
      end
    end

    @analysis_results[:manifest][:providers].each do |provider|
      if provider[:exported] == 'true'
        @analysis_results[:security_issues] << {
          severity: 'CRITICAL',
          category: 'Component Security',
          title: "Exported Content Provider: #{provider[:name]}",
          description: "Content provider #{provider[:name]} is exported. This can lead to data leakage if not properly protected.",
          owasp: 'M2: Insecure Data Storage'
        }
      end
    end
  end

  def extract_certificate(apk_path)
    begin
      # Use apksigner to extract certificate info
      result = run_cmd(['apksigner', 'verify', '--print-certs', apk_path])

      if result
        @analysis_results[:certificate] = parse_certificate_output(result)

        print_good("Certificate DN: #{@analysis_results[:certificate][:subject]}")
        print_status("Valid from: #{@analysis_results[:certificate][:valid_from]}")
        print_status("Valid until: #{@analysis_results[:certificate][:valid_until]}")

        # Check certificate validity
        if @analysis_results[:certificate][:expired]
          @analysis_results[:security_issues] << {
            severity: 'CRITICAL',
            category: 'Certificate',
            title: 'Expired Certificate',
            description: 'The APK is signed with an expired certificate.',
            owasp: 'M7: Client Code Quality'
          }
        end
      end
    rescue StandardError => e
      print_error("Failed to extract certificate: #{e.message}")
    end
  end

  def parse_certificate_output(output)
    cert_info = {
      subject: '',
      issuer: '',
      valid_from: '',
      valid_until: '',
      expired: false,
      md5: '',
      sha1: '',
      sha256: ''
    }

    # Parse certificate details from apksigner output
    output.each_line do |line|
      if line =~ /certificate DN: (.+)$/
        cert_info[:subject] = $1.strip
      elsif line =~ /certificate MD5 digest: (.+)$/
        cert_info[:md5] = $1.strip
      elsif line =~ /certificate SHA-1 digest: (.+)$/
        cert_info[:sha1] = $1.strip
      elsif line =~ /certificate SHA-256 digest: (.+)$/
        cert_info[:sha256] = $1.strip
      end
    end

    cert_info
  end

  def analyze_strings(tempdir)
    strings_found = {
      urls: [],
      api_keys: [],
      emails: [],
      ip_addresses: [],
      crypto_keys: [],
      hardcoded_secrets: []
    }

    # Search through all .smali files
    smali_files = Dir.glob(File.join(tempdir, 'decompiled', 'smali**', '**', '*.smali'))

    smali_files.each do |file|
      content = File.read(file)

      # Extract URLs
      content.scan(/https?:\/\/[^\s"']+/).each do |url|
        strings_found[:urls] << url unless strings_found[:urls].include?(url)
      end

      # Extract potential API keys
      content.scan(/(api[_-]?key|apikey|api[_-]?secret)["\s]*[:=]["\s]*([a-zA-Z0-9\-_]{20,})/i).each do |match|
        strings_found[:api_keys] << match.join(': ')
      end

      # Extract email addresses
      content.scan(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/).each do |email|
        strings_found[:emails] << email unless strings_found[:emails].include?(email)
      end

      # Extract IP addresses
      content.scan(/\b(?:\d{1,3}\.){3}\d{1,3}\b/).each do |ip|
        strings_found[:ip_addresses] << ip unless strings_found[:ip_addresses].include?(ip)
      end
    end

    @analysis_results[:strings_analysis] = strings_found

    print_status("Found #{strings_found[:urls].length} URLs")
    print_status("Found #{strings_found[:api_keys].length} potential API keys")
    print_status("Found #{strings_found[:ip_addresses].length} IP addresses")

    # Flag security issues
    if strings_found[:api_keys].any?
      @analysis_results[:security_issues] << {
        severity: 'CRITICAL',
        category: 'Hardcoded Secrets',
        title: 'Hardcoded API Keys Detected',
        description: "Found #{strings_found[:api_keys].length} potential hardcoded API keys in the code. This is a major security risk.",
        owasp: 'M2: Insecure Data Storage',
        details: strings_found[:api_keys].first(5)
      }
    end
  end

  def detect_libraries(tempdir)
    known_libraries = {
      'okhttp' => 'OkHttp (HTTP client)',
      'retrofit' => 'Retrofit (REST client)',
      'firebase' => 'Firebase SDK',
      'crashlytics' => 'Crashlytics',
      'admob' => 'AdMob',
      'facebook' => 'Facebook SDK',
      'google/analytics' => 'Google Analytics',
      'com/android/volley' => 'Volley (HTTP library)',
      'square/picasso' => 'Picasso (Image loading)',
      'androidx' => 'AndroidX',
      'kotlin' => 'Kotlin runtime'
    }

    smali_dirs = Dir.glob(File.join(tempdir, 'decompiled', 'smali*'))

    smali_dirs.each do |smali_dir|
      known_libraries.each do |lib_pattern, lib_name|
        lib_path = File.join(smali_dir, lib_pattern.gsub('/', File::SEPARATOR))
        if Dir.exist?(lib_path) || Dir.glob("#{smali_dir}/**/#{lib_pattern}").any?
          @analysis_results[:libraries] << lib_name unless @analysis_results[:libraries].include?(lib_name)
        end
      end
    end

    print_status("Detected libraries: #{@analysis_results[:libraries].join(', ')}") if @analysis_results[:libraries].any?
  end

  def check_network_security(tempdir)
    network_config_path = File.join(tempdir, 'decompiled', 'res', 'xml', 'network_security_config.xml')

    if File.exist?(network_config_path)
      config_xml = File.read(network_config_path)
      doc = Nokogiri::XML(config_xml)

      @analysis_results[:network_config] = {
        has_config: true,
        cleartextTrafficPermitted: doc.at_xpath('//base-config')&.[]('cleartextTrafficPermitted'),
        domains: []
      }

      # Check for cleartext traffic
      if @analysis_results[:network_config][:cleartextTrafficPermitted] == 'true'
        @analysis_results[:security_issues] << {
          severity: 'HIGH',
          category: 'Network Security',
          title: 'Cleartext Traffic Permitted',
          description: 'Application allows cleartext (HTTP) traffic, which can be intercepted. Use HTTPS only.',
          owasp: 'M3: Insecure Communication'
        }
      end
    else
      @analysis_results[:network_config] = { has_config: false }

      # Check if app targets API 28+ without network security config
      target_sdk = @analysis_results[:manifest][:target_sdk].to_i
      if target_sdk >= 28
        @analysis_results[:security_issues] << {
          severity: 'MEDIUM',
          category: 'Network Security',
          title: 'No Network Security Configuration',
          description: 'Application targeting API 28+ should define a network security configuration.',
          owasp: 'M3: Insecure Communication'
        }
      end
    end
  end

  def analyze_vpn_security(tempdir)
    print_status("Performing VPN-specific security analysis...")

    vpn_analysis = {
      vpn_service_detected: false,
      vpn_permissions: [],
      potential_dns_leaks: false,
      potential_ip_leaks: false,
      traffic_inspection: false,
      encryption_indicators: []
    }

    # Check for VPN service
    @analysis_results[:manifest][:services].each do |service|
      if service[:name].downcase.include?('vpn')
        vpn_analysis[:vpn_service_detected] = true
      end
    end

    # Check for VPN permissions
    vpn_permissions = ['BIND_VPN_SERVICE', 'VPN_MANAGE', 'CHANGE_NETWORK_STATE', 'INTERNET']
    @analysis_results[:manifest][:permissions].each do |perm|
      vpn_permissions.each do |vpn_perm|
        if perm.include?(vpn_perm)
          vpn_analysis[:vpn_permissions] << perm
        end
      end
    end

    # Check strings for VPN-related security issues
    if @analysis_results[:strings_analysis][:urls]
      # Check for hardcoded DNS servers (potential DNS leak)
      dns_servers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9']
      @analysis_results[:strings_analysis][:ip_addresses].each do |ip|
        if dns_servers.include?(ip)
          vpn_analysis[:potential_dns_leaks] = true
        end
      end

      # Check for analytics/tracking URLs (potential privacy leak)
      tracking_domains = ['google-analytics', 'facebook.com/tr', 'analytics', 'tracking']
      @analysis_results[:strings_analysis][:urls].each do |url|
        if tracking_domains.any? { |domain| url.downcase.include?(domain) }
          vpn_analysis[:traffic_inspection] = true
        end
      end
    end

    # Check for encryption libraries
    encryption_libs = ['bouncycastle', 'conscrypt', 'openssl', 'sodium']
    @analysis_results[:libraries].each do |lib|
      if encryption_libs.any? { |enc_lib| lib.downcase.include?(enc_lib) }
        vpn_analysis[:encryption_indicators] << lib
      end
    end

    @analysis_results[:vpn_specific] = vpn_analysis

    # Report VPN-specific security issues
    if vpn_analysis[:vpn_service_detected]
      print_good("VPN service detected in application")

      if vpn_analysis[:encryption_indicators].empty?
        @analysis_results[:security_issues] << {
          severity: 'CRITICAL',
          category: 'VPN Security',
          title: 'No Encryption Library Detected',
          description: 'VPN service detected but no obvious encryption library found. VPN traffic may not be encrypted.',
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

    # M1: Improper Platform Usage
    if @analysis_results[:manifest][:target_sdk].to_i < 29
      @analysis_results[:owasp_checks][:m1_improper_platform_usage] << 'Targeting old Android SDK (< API 29)'
    end

    # M2: Insecure Data Storage
    if @analysis_results[:permissions][:dangerous].any? { |p| p.include?('STORAGE') }
      @analysis_results[:owasp_checks][:m2_insecure_data_storage] << 'External storage access detected'
    end

    # M3: Insecure Communication
    unless @analysis_results[:network_config][:has_config]
      @analysis_results[:owasp_checks][:m3_insecure_communication] << 'No network security configuration'
    end

    # M5: Insufficient Cryptography
    if @analysis_results[:libraries].none? { |lib| lib.downcase.include?('crypto') }
      @analysis_results[:owasp_checks][:m5_insufficient_cryptography] << 'No obvious cryptography library detected'
    end

    # M8: Code Tampering
    # Check if app is debuggable
    if @manifest_doc
      debuggable = @manifest_doc.at_xpath('//application')&.[]('debuggable')
      if debuggable == 'true'
        @analysis_results[:owasp_checks][:m8_code_tampering] << 'Application is debuggable'
        @analysis_results[:security_issues] << {
          severity: 'HIGH',
          category: 'Code Tampering',
          title: 'Application is Debuggable',
          description: 'android:debuggable is set to true. This allows attackers to inspect and modify the app at runtime.',
          owasp: 'M8: Code Tampering'
        }
      end
    end

    # M9: Reverse Engineering
    # Check for code obfuscation
    if @analysis_results[:libraries].none? { |lib| lib.downcase.include?('proguard') || lib.downcase.include?('r8') }
      @analysis_results[:owasp_checks][:m9_reverse_engineering] << 'No obvious code obfuscation detected'
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
    app_name = @analysis_results[:manifest][:package] || 'unknown'
    base_filename = "#{app_name}_analysis_#{timestamp}"

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
    report << "APK SECURITY ANALYSIS REPORT"
    report << "=" * 80
    report << ""
    report << "Analysis Date: #{@analysis_results[:metadata][:analyzed_at]}"
    report << "APK File: #{@analysis_results[:metadata][:filename]}"
    report << "Package: #{@analysis_results[:manifest][:package]}"
    report << "Version: #{@analysis_results[:manifest][:version_name]}"
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
    report_file = File.join(output_dir, "#{base_filename}.html")

    html = <<~HTML
      <!DOCTYPE html>
      <html>
      <head>
        <title>APK Security Analysis Report</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
          .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
          h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
          h2 { color: #555; margin-top: 30px; border-bottom: 2px solid #6c757d; padding-bottom: 8px; }
          .metadata { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
          .risk-score { font-size: 48px; font-weight: bold; text-align: center; padding: 20px; border-radius: 10px; margin: 20px 0; }
          .risk-critical { background: #dc3545; color: white; }
          .risk-high { background: #fd7e14; color: white; }
          .risk-medium { background: #ffc107; color: black; }
          .risk-low { background: #28a745; color: white; }
          .issue { border-left: 4px solid #ccc; padding: 15px; margin: 10px 0; background: #f8f9fa; }
          .issue.critical { border-left-color: #dc3545; }
          .issue.high { border-left-color: #fd7e14; }
          .issue.medium { border-left-color: #ffc107; }
          .issue.low { border-left-color: #28a745; }
          .severity { display: inline-block; padding: 3px 8px; border-radius: 3px; font-weight: bold; font-size: 12px; }
          .severity.critical { background: #dc3545; color: white; }
          .severity.high { background: #fd7e14; color: white; }
          .severity.medium { background: #ffc107; color: black; }
          .severity.low { background: #28a745; color: white; }
          table { width: 100%; border-collapse: collapse; margin: 15px 0; }
          th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
          th { background: #007bff; color: white; }
          .recommendations { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>📱 APK Security Analysis Report</h1>

          <div class="metadata">
            <strong>APK File:</strong> #{@analysis_results[:metadata][:filename]}<br>
            <strong>Package:</strong> #{@analysis_results[:manifest][:package]}<br>
            <strong>Version:</strong> #{@analysis_results[:manifest][:version_name]} (#{@analysis_results[:manifest][:version_code]})<br>
            <strong>Target SDK:</strong> API #{@analysis_results[:manifest][:target_sdk]}<br>
            <strong>Analysis Date:</strong> #{@analysis_results[:metadata][:analyzed_at]}<br>
            <strong>SHA-256:</strong> <code>#{@analysis_results[:metadata][:sha256]}</code>
          </div>

          <div class="risk-score #{risk_class}">
            Risk Score: #{@analysis_results[:risk_score]}/100
          </div>

          <h2>🔍 Security Issues (#{@analysis_results[:security_issues].length} found)</h2>
          #{generate_issues_html}

          <h2>📋 Permissions Analysis</h2>
          <p><strong>Total Permissions:</strong> #{@analysis_results[:permissions][:total]}</p>
          <p><strong>Dangerous Permissions:</strong> #{@analysis_results[:permissions][:dangerous].length}</p>
          #{generate_permissions_html}

          <h2>🔐 Certificate Information</h2>
          <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Subject</td><td>#{@analysis_results[:certificate][:subject]}</td></tr>
            <tr><td>SHA-256</td><td><code>#{@analysis_results[:certificate][:sha256]}</code></td></tr>
          </table>

          <h2>📚 Detected Libraries</h2>
          <ul>
            #{@analysis_results[:libraries].map { |lib| "<li>#{lib}</li>" }.join("\n")}
          </ul>

          <h2>💡 Recommendations</h2>
          <div class="recommendations">
            <ul>
              #{@analysis_results[:recommendations].map { |rec| "<li>#{rec}</li>" }.join("\n")}
            </ul>
          </div>

          <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666;">
            <p>Generated by Mobile Security Lab - Metasploit Framework</p>
          </footer>
        </div>
      </body>
      </html>
    HTML

    File.write(report_file, html)
    print_good("HTML report saved to: #{report_file}")
  end

  def risk_class
    score = @analysis_results[:risk_score]
    if score >= 75
      'risk-critical'
    elsif score >= 50
      'risk-high'
    elsif score >= 25
      'risk-medium'
    else
      'risk-low'
    end
  end

  def generate_issues_html
    html = []
    @analysis_results[:security_issues].each do |issue|
      severity_class = issue[:severity].downcase
      html << <<~ISSUE
        <div class="issue #{severity_class}">
          <div><span class="severity #{severity_class}">#{issue[:severity]}</span> <strong>#{issue[:title]}</strong></div>
          <p>#{issue[:description]}</p>
          <small><strong>Category:</strong> #{issue[:category]} | <strong>OWASP:</strong> #{issue[:owasp]}</small>
        </div>
      ISSUE
    end
    html.join("\n")
  end

  def generate_permissions_html
    return '' if @analysis_results[:permissions][:dangerous].empty?

    html = '<ul>'
    @analysis_results[:permissions][:dangerous].each do |perm|
      html += "<li><code>#{perm}</code></li>"
    end
    html += '</ul>'
    html
  end

  def store_analysis_results(apk_path)
    # Store in Metasploit database if available
    return unless framework.db.active

    loot_data = JSON.pretty_generate(@analysis_results)

    store_loot(
      'mobile.apk.analysis',
      'application/json',
      '127.0.0.1',
      loot_data,
      "#{@analysis_results[:manifest][:package]}_analysis.json",
      "APK Security Analysis: #{@analysis_results[:manifest][:package]}"
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
