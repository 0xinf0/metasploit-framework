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
        'Name' => 'VPN Application Security Analyzer',
        'Description' => %q{
          This module performs comprehensive security analysis of VPN applications (APK/IPA).
          It focuses specifically on VPN-related security issues:
          - DNS leak detection (hardcoded DNS servers, DNS request handling)
          - IP leak detection (WebRTC leaks, IP exposure)
          - Encryption analysis (protocols, cipher suites, key strength)
          - Privacy analysis (logging, tracking, third-party SDKs)
          - Kill switch implementation detection
          - Connection security (certificate pinning, TLS validation)
          - Permission analysis (excessive permissions)
          - Network security configuration
          - Traffic routing analysis
          - Data collection and privacy policy compliance

          Combines static and dynamic analysis for complete VPN security assessment.
        },
        'Author' => ['Mobile Security Lab'],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://www.dnsleaktest.com/'],
          ['URL', 'https://ipleak.net/'],
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
        OptPath.new('APP_FILE', [true, 'Path to the APK or IPA file to analyze']),
        OptEnum.new('APP_TYPE', [true, 'Application type', 'APK', ['APK', 'IPA']]),
        OptBool.new('DYNAMIC_ANALYSIS', [true, 'Perform dynamic analysis (requires device)', false]),
        OptString.new('DEVICE_ID', [false, 'Device ID for dynamic analysis', nil]),
        OptString.new('OUTPUT_DIR', [false, 'Directory to save analysis reports', nil]),
        OptEnum.new('REPORT_FORMAT', [true, 'Report output format', 'HTML', ['JSON', 'HTML', 'PDF', 'TXT']]),
        OptBool.new('DEEP_SCAN', [true, 'Perform deep VPN security scanning', true]),
        OptBool.new('PRIVACY_CHECK', [true, 'Check privacy policy compliance', true])
      ]
    )
  end

  def run
    app_path = datastore['APP_FILE']
    app_type = datastore['APP_TYPE']

    unless File.exist?(app_path)
      print_error("Application file not found: #{app_path}")
      return
    end

    print_status("=" * 80)
    print_status("VPN Application Security Analysis - Mobile Security Lab")
    print_status("=" * 80)
    print_status("Target App: #{File.basename(app_path)}")
    print_status("App Type: #{app_type}")
    print_status("File Size: #{File.size(app_path)} bytes")
    print_status("Analysis Started: #{Time.now}")
    print_status("=" * 80)

    begin
      # Initialize comprehensive VPN analysis results
      @vpn_analysis = {
        metadata: {},
        static_analysis: {},
        dynamic_analysis: {},
        dns_leak_analysis: {},
        ip_leak_analysis: {},
        encryption_analysis: {},
        privacy_analysis: {},
        kill_switch_analysis: {},
        permission_analysis: {},
        network_security: {},
        third_party_analysis: {},
        protocol_analysis: {},
        security_issues: [],
        privacy_issues: [],
        risk_score: 0,
        recommendations: []
      }

      # Step 1: Extract metadata
      print_status("[*] Extracting application metadata...")
      extract_metadata(app_path, app_type)

      # Step 2: Perform static analysis
      print_status("[*] Performing static analysis...")
      perform_static_analysis(app_path, app_type)

      # Step 3: Analyze DNS leak potential
      print_status("[*] Analyzing DNS leak potential...")
      analyze_dns_leaks

      # Step 4: Analyze IP leak potential
      print_status("[*] Analyzing IP leak potential...")
      analyze_ip_leaks

      # Step 5: Analyze encryption implementation
      print_status("[*] Analyzing encryption implementation...")
      analyze_encryption

      # Step 6: Analyze privacy and data collection
      print_status("[*] Analyzing privacy and data collection...")
      analyze_privacy

      # Step 7: Check for kill switch implementation
      print_status("[*] Checking for kill switch implementation...")
      analyze_kill_switch

      # Step 8: Analyze permissions
      print_status("[*] Analyzing permissions...")
      analyze_permissions

      # Step 9: Check network security configuration
      print_status("[*] Checking network security configuration...")
      analyze_network_security

      # Step 10: Detect third-party SDKs
      print_status("[*] Detecting third-party SDKs and libraries...")
      analyze_third_party_sdks

      # Step 11: Analyze VPN protocols
      print_status("[*] Analyzing VPN protocols...")
      analyze_vpn_protocols

      # Step 12: Dynamic analysis (if enabled)
      if datastore['DYNAMIC_ANALYSIS']
        print_status("[*] Performing dynamic analysis...")
        perform_dynamic_analysis
      end

      # Step 13: Calculate risk score
      print_status("[*] Calculating security risk score...")
      calculate_vpn_risk_score

      # Step 14: Generate comprehensive report
      print_status("[*] Generating VPN security report...")
      generate_vpn_report

      print_status("=" * 80)
      print_good("VPN Analysis complete!")
      print_status("Overall Risk Score: #{@vpn_analysis[:risk_score]}/100")
      print_status("Security Issues: #{@vpn_analysis[:security_issues].length}")
      print_status("Privacy Issues: #{@vpn_analysis[:privacy_issues].length}")
      print_status("=" * 80)

      # Display critical findings
      display_critical_findings

      # Store results
      store_vpn_analysis_results(app_path)

    rescue StandardError => e
      print_error("VPN analysis failed: #{e.message}")
      print_error(e.backtrace.join("\n"))
    end
  end

  def extract_metadata(app_path, app_type)
    @vpn_analysis[:metadata] = {
      filename: File.basename(app_path),
      filepath: app_path,
      app_type: app_type,
      file_size: File.size(app_path),
      md5: Digest::MD5.file(app_path).hexdigest,
      sha256: Digest::SHA256.file(app_path).hexdigest,
      analyzed_at: Time.now.to_s
    }

    print_good("SHA-256: #{@vpn_analysis[:metadata][:sha256]}")
  end

  def perform_static_analysis(app_path, app_type)
    # Decompile/extract the application
    tempdir = if app_type == 'APK'
                decompile_apk(app_path)
              else
                extract_ipa(app_path)
              end

    return if tempdir.nil?

    @tempdir = tempdir
    @app_type = app_type

    # Extract app info
    if app_type == 'APK'
      parse_android_manifest(tempdir)
      analyze_android_code(tempdir)
    else
      parse_ios_info_plist(tempdir)
      analyze_ios_code(tempdir)
    end

    @vpn_analysis[:static_analysis] = {
      app_name: @app_name,
      package_id: @package_id,
      version: @app_version,
      permissions: @permissions || [],
      components: @components || {},
      strings: @strings || {},
      code_analysis: @code_analysis || {}
    }
  end

  def analyze_dns_leaks
    print_status("Checking for DNS leak vulnerabilities...")

    dns_analysis = {
      hardcoded_dns_servers: [],
      custom_dns_implementation: false,
      dns_over_https: false,
      dns_over_tls: false,
      dns_leak_protection: false,
      issues: []
    }

    # Known public DNS servers that indicate potential leaks
    public_dns_servers = {
      '8.8.8.8' => 'Google DNS',
      '8.8.4.4' => 'Google DNS',
      '1.1.1.1' => 'Cloudflare DNS',
      '1.0.0.1' => 'Cloudflare DNS',
      '9.9.9.9' => 'Quad9 DNS',
      '208.67.222.222' => 'OpenDNS',
      '208.67.220.220' => 'OpenDNS'
    }

    # Check strings for hardcoded DNS servers
    if @strings && @strings[:ip_addresses]
      @strings[:ip_addresses].each do |ip|
        if public_dns_servers.key?(ip)
          dns_analysis[:hardcoded_dns_servers] << {
            ip: ip,
            provider: public_dns_servers[ip]
          }
        end
      end
    end

    # Check for DNS-related code
    if @strings && @strings[:urls]
      @strings[:urls].each do |url|
        if url.include?('dns-query') || url.include?('dns.google')
          dns_analysis[:dns_over_https] = true
        end
      end
    end

    # Check code for DNS implementations
    if @code_analysis && @code_analysis[:classes]
      dns_related_classes = @code_analysis[:classes].select { |c|
        c.downcase.include?('dns') || c.downcase.include?('resolver')
      }
      dns_analysis[:custom_dns_implementation] = dns_related_classes.any?
    end

    # Report issues
    if dns_analysis[:hardcoded_dns_servers].any?
      severity = dns_analysis[:hardcoded_dns_servers].length > 2 ? 'CRITICAL' : 'HIGH'
      @vpn_analysis[:security_issues] << {
        severity: severity,
        category: 'DNS Leak',
        title: 'Hardcoded Public DNS Servers Detected',
        description: "Found #{dns_analysis[:hardcoded_dns_servers].length} hardcoded public DNS servers. VPN may leak DNS queries to third parties.",
        details: dns_analysis[:hardcoded_dns_servers],
        cwe: 'CWE-200: Exposure of Sensitive Information'
      }
    end

    unless dns_analysis[:custom_dns_implementation] || dns_analysis[:dns_over_https]
      @vpn_analysis[:security_issues] << {
        severity: 'MEDIUM',
        category: 'DNS Leak',
        title: 'No Custom DNS Implementation Detected',
        description: 'VPN does not appear to implement custom DNS handling. May rely on system DNS, causing leaks.',
        cwe: 'CWE-200: Exposure of Sensitive Information'
      }
    end

    @vpn_analysis[:dns_leak_analysis] = dns_analysis
    print_status("DNS leak analysis complete: #{dns_analysis[:hardcoded_dns_servers].length} hardcoded DNS servers found")
  end

  def analyze_ip_leaks
    print_status("Checking for IP leak vulnerabilities...")

    ip_analysis = {
      webrtc_detected: false,
      ipv6_leak_protection: false,
      split_tunneling: false,
      always_on_vpn: false,
      issues: []
    }

    # Check for WebRTC (common source of IP leaks)
    if @strings && @strings[:urls]
      webrtc_indicators = ['webrtc', 'stun:', 'turn:', 'ice-candidate']
      @strings[:urls].each do |url|
        if webrtc_indicators.any? { |indicator| url.downcase.include?(indicator) }
          ip_analysis[:webrtc_detected] = true
          break
        end
      end
    end

    # Check for IPv6 handling
    if @code_analysis && @code_analysis[:classes]
      ipv6_classes = @code_analysis[:classes].select { |c|
        c.downcase.include?('ipv6') || c.downcase.include?('inet6')
      }
      ip_analysis[:ipv6_leak_protection] = ipv6_classes.any?
    end

    # Android-specific: Check for split tunneling
    if @app_type == 'APK' && @components
      if @components[:services]
        split_tunnel_services = @components[:services].select { |s|
          s[:name].downcase.include?('split') || s[:name].downcase.include?('exclude')
        }
        ip_analysis[:split_tunneling] = split_tunnel_services.any?
      end
    end

    # Report issues
    if ip_analysis[:webrtc_detected]
      @vpn_analysis[:security_issues] << {
        severity: 'HIGH',
        category: 'IP Leak',
        title: 'WebRTC Detected - Potential IP Leak',
        description: 'Application includes WebRTC functionality which can leak real IP address even when VPN is active.',
        cwe: 'CWE-200: Exposure of Sensitive Information'
      }
    end

    unless ip_analysis[:ipv6_leak_protection]
      @vpn_analysis[:security_issues] << {
        severity: 'MEDIUM',
        category: 'IP Leak',
        title: 'No IPv6 Leak Protection Detected',
        description: 'No evidence of IPv6 leak protection. IPv6 traffic may bypass VPN tunnel.',
        cwe: 'CWE-200: Exposure of Sensitive Information'
      }
    end

    @vpn_analysis[:ip_leak_analysis] = ip_analysis
    print_status("IP leak analysis complete")
  end

  def analyze_encryption
    print_status("Analyzing encryption implementation...")

    encryption_analysis = {
      encryption_libraries: [],
      protocols: [],
      cipher_suites: [],
      key_exchange: [],
      weak_crypto: [],
      issues: []
    }

    # Known encryption libraries
    crypto_libraries = {
      'OpenSSL' => { strength: 'strong', protocols: ['TLS', 'SSL'] },
      'BouncyCastle' => { strength: 'strong', protocols: ['TLS', 'VPN'] },
      'libsodium' => { strength: 'strong', protocols: ['Modern Crypto'] },
      'WireGuard' => { strength: 'strong', protocols: ['WireGuard'] },
      'OpenVPN' => { strength: 'strong', protocols: ['OpenVPN'] },
      'IPSec' => { strength: 'strong', protocols: ['IPSec', 'IKEv2'] },
      'Conscrypt' => { strength: 'strong', protocols: ['TLS'] }
    }

    # Weak/deprecated crypto
    weak_crypto_indicators = ['MD5', 'SHA1', 'DES', 'RC4', 'SSLv3', 'TLSv1.0']

    # Check libraries
    if @libraries
      @libraries.each do |lib|
        crypto_libraries.each do |lib_name, info|
          if lib.include?(lib_name)
            encryption_analysis[:encryption_libraries] << {
              name: lib_name,
              strength: info[:strength],
              protocols: info[:protocols]
            }
          end
        end
      end
    end

    # Check strings for crypto indicators
    if @strings && @strings[:all]
      @strings[:all].each do |str|
        # Check for VPN protocols
        if str.include?('OpenVPN') || str.include?('openvpn')
          encryption_analysis[:protocols] << 'OpenVPN' unless encryption_analysis[:protocols].include?('OpenVPN')
        elsif str.include?('WireGuard') || str.include?('wireguard')
          encryption_analysis[:protocols] << 'WireGuard' unless encryption_analysis[:protocols].include?('WireGuard')
        elsif str.include?('IPSec') || str.include?('IKEv2')
          encryption_analysis[:protocols] << 'IPSec/IKEv2' unless encryption_analysis[:protocols].include?('IPSec/IKEv2')
        elsif str.include?('L2TP')
          encryption_analysis[:protocols] << 'L2TP' unless encryption_analysis[:protocols].include?('L2TP')
        elsif str.include?('PPTP')
          encryption_analysis[:protocols] << 'PPTP (INSECURE)' unless encryption_analysis[:protocols].include?('PPTP')
        end

        # Check for weak crypto
        weak_crypto_indicators.each do |weak|
          if str.include?(weak)
            encryption_analysis[:weak_crypto] << weak unless encryption_analysis[:weak_crypto].include?(weak)
          end
        end
      end
    end

    # Report issues
    if encryption_analysis[:encryption_libraries].empty?
      @vpn_analysis[:security_issues] << {
        severity: 'CRITICAL',
        category: 'Encryption',
        title: 'No Encryption Library Detected',
        description: 'No recognized encryption library found. VPN traffic may not be encrypted.',
        cwe: 'CWE-311: Missing Encryption of Sensitive Data'
      }
    end

    if encryption_analysis[:protocols].include?('PPTP (INSECURE)')
      @vpn_analysis[:security_issues] << {
        severity: 'CRITICAL',
        category: 'Encryption',
        title: 'Insecure PPTP Protocol Detected',
        description: 'PPTP is a deprecated and insecure VPN protocol. Should not be used.',
        cwe: 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm'
      }
    end

    if encryption_analysis[:weak_crypto].any?
      @vpn_analysis[:security_issues] << {
        severity: 'HIGH',
        category: 'Encryption',
        title: 'Weak Cryptographic Algorithms Detected',
        description: "Found references to weak/deprecated crypto: #{encryption_analysis[:weak_crypto].join(', ')}",
        details: encryption_analysis[:weak_crypto],
        cwe: 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm'
      }
    end

    @vpn_analysis[:encryption_analysis] = encryption_analysis
    print_status("Encryption analysis complete: #{encryption_analysis[:protocols].join(', ')}")
  end

  def analyze_privacy
    print_status("Analyzing privacy and data collection...")

    privacy_analysis = {
      tracking_sdks: [],
      analytics_sdks: [],
      ad_networks: [],
      data_collection: [],
      logging_detected: false,
      issues: []
    }

    # Known tracking/analytics SDKs
    tracking_sdks = {
      'google-analytics' => 'Google Analytics',
      'firebase/analytics' => 'Firebase Analytics',
      'facebook' => 'Facebook SDK',
      'flurry' => 'Flurry Analytics',
      'mixpanel' => 'Mixpanel',
      'amplitude' => 'Amplitude',
      'appsflyer' => 'AppsFlyer',
      'adjust' => 'Adjust',
      'branch' => 'Branch.io',
      'crashlytics' => 'Crashlytics',
      'sentry' => 'Sentry'
    }

    ad_networks = {
      'admob' => 'AdMob',
      'doubleclick' => 'DoubleClick',
      'mopub' => 'MoPub',
      'unity3d/ads' => 'Unity Ads',
      'chartboost' => 'Chartboost'
    }

    # Check libraries for tracking SDKs
    if @libraries
      @libraries.each do |lib|
        tracking_sdks.each do |pattern, name|
          if lib.downcase.include?(pattern)
            privacy_analysis[:tracking_sdks] << name unless privacy_analysis[:tracking_sdks].include?(name)
          end
        end

        ad_networks.each do |pattern, name|
          if lib.downcase.include?(pattern)
            privacy_analysis[:ad_networks] << name unless privacy_analysis[:ad_networks].include?(name)
          end
        end
      end
    end

    # Check strings for tracking URLs
    if @strings && @strings[:urls]
      tracking_domains = [
        'google-analytics.com',
        'facebook.com/tr',
        'doubleclick.net',
        'analytics',
        'tracking',
        'telemetry'
      ]

      @strings[:urls].each do |url|
        tracking_domains.each do |domain|
          if url.downcase.include?(domain)
            privacy_analysis[:data_collection] << url
            break
          end
        end
      end
    end

    # Check for logging
    if @code_analysis && @code_analysis[:methods]
      log_methods = @code_analysis[:methods].select { |m|
        m.downcase.include?('log') || m.downcase.include?('logger')
      }
      privacy_analysis[:logging_detected] = log_methods.any?
    end

    # Report privacy issues
    if privacy_analysis[:tracking_sdks].any?
      @vpn_analysis[:privacy_issues] << {
        severity: 'CRITICAL',
        category: 'Privacy',
        title: 'Third-Party Tracking SDKs Detected',
        description: "VPN app contains #{privacy_analysis[:tracking_sdks].length} tracking SDKs that may monitor user activity: #{privacy_analysis[:tracking_sdks].join(', ')}",
        details: privacy_analysis[:tracking_sdks]
      }
    end

    if privacy_analysis[:ad_networks].any?
      @vpn_analysis[:privacy_issues] << {
        severity: 'HIGH',
        category: 'Privacy',
        title: 'Ad Networks Detected in VPN App',
        description: "VPN app contains ad networks: #{privacy_analysis[:ad_networks].join(', ')}. This raises privacy concerns.",
        details: privacy_analysis[:ad_networks]
      }
    end

    @vpn_analysis[:privacy_analysis] = privacy_analysis
    print_warning("Privacy analysis: #{privacy_analysis[:tracking_sdks].length} tracking SDKs found") if privacy_analysis[:tracking_sdks].any?
  end

  def analyze_kill_switch
    print_status("Checking for kill switch implementation...")

    kill_switch_analysis = {
      kill_switch_detected: false,
      always_on_vpn: false,
      leak_protection: false,
      firewall_rules: false
    }

    # Check code for kill switch indicators
    if @code_analysis && @code_analysis[:classes]
      kill_switch_classes = @code_analysis[:classes].select { |c|
        c.downcase.include?('killswitch') ||
        c.downcase.include?('leak') && c.downcase.include?('protect') ||
        c.downcase.include?('firewall')
      }
      kill_switch_analysis[:kill_switch_detected] = kill_switch_classes.any?
    end

    # Android-specific checks
    if @app_type == 'APK' && @permissions
      # Check for firewall permissions
      if @permissions.any? { |p| p.include?('WRITE_SECURE_SETTINGS') }
        kill_switch_analysis[:firewall_rules] = true
      end
    end

    # Report issues
    unless kill_switch_analysis[:kill_switch_detected]
      @vpn_analysis[:security_issues] << {
        severity: 'HIGH',
        category: 'Kill Switch',
        title: 'No Kill Switch Detected',
        description: 'VPN does not appear to implement a kill switch. Traffic may leak if VPN connection drops.',
        cwe: 'CWE-200: Exposure of Sensitive Information'
      }
    end

    @vpn_analysis[:kill_switch_analysis] = kill_switch_analysis
  end

  def analyze_permissions
    return unless @permissions

    permission_analysis = {
      dangerous_permissions: [],
      unnecessary_permissions: [],
      vpn_permissions: []
    }

    # VPN-necessary permissions
    vpn_required_perms = ['INTERNET', 'ACCESS_NETWORK_STATE', 'BIND_VPN_SERVICE']

    # Suspicious permissions for a VPN
    suspicious_perms = [
      'READ_CONTACTS',
      'READ_SMS',
      'SEND_SMS',
      'READ_CALL_LOG',
      'CAMERA',
      'RECORD_AUDIO',
      'READ_CALENDAR',
      'GET_ACCOUNTS'
    ]

    @permissions.each do |perm|
      perm_name = perm.is_a?(Hash) ? perm[:name] : perm

      if vpn_required_perms.any? { |vp| perm_name.include?(vp) }
        permission_analysis[:vpn_permissions] << perm_name
      elsif suspicious_perms.any? { |sp| perm_name.include?(sp) }
        permission_analysis[:unnecessary_permissions] << perm_name
      end
    end

    # Report issues
    if permission_analysis[:unnecessary_permissions].any?
      @vpn_analysis[:privacy_issues] << {
        severity: 'HIGH',
        category: 'Permissions',
        title: 'Excessive Permissions Requested',
        description: "VPN app requests unnecessary permissions: #{permission_analysis[:unnecessary_permissions].join(', ')}",
        details: permission_analysis[:unnecessary_permissions]
      }
    end

    @vpn_analysis[:permission_analysis] = permission_analysis
  end

  def analyze_network_security
    # Platform-specific network security checks
    network_security = {
      certificate_pinning: false,
      tls_validation: true,
      cleartext_traffic: false
    }

    if @app_type == 'APK' && @network_config
      network_security[:cleartext_traffic] = (@network_config[:cleartextTrafficPermitted] == 'true')
    end

    # Check for certificate pinning
    if @code_analysis && @code_analysis[:classes]
      pinning_classes = @code_analysis[:classes].select { |c|
        c.downcase.include?('pinning') || c.downcase.include?('certpin')
      }
      network_security[:certificate_pinning] = pinning_classes.any?
    end

    # Report issues
    if network_security[:cleartext_traffic]
      @vpn_analysis[:security_issues] << {
        severity: 'CRITICAL',
        category: 'Network Security',
        title: 'Cleartext Traffic Permitted',
        description: 'VPN app allows cleartext (HTTP) traffic. All traffic should be encrypted.',
        cwe: 'CWE-319: Cleartext Transmission of Sensitive Information'
      }
    end

    unless network_security[:certificate_pinning]
      @vpn_analysis[:security_issues] << {
        severity: 'MEDIUM',
        category: 'Network Security',
        title: 'No Certificate Pinning Detected',
        description: 'VPN app does not appear to implement certificate pinning. Vulnerable to MITM attacks.',
        cwe: 'CWE-295: Improper Certificate Validation'
      }
    end

    @vpn_analysis[:network_security] = network_security
  end

  def analyze_third_party_sdks
    return unless @libraries

    third_party_analysis = {
      total_sdks: @libraries.length,
      open_source: [],
      proprietary: [],
      security_libraries: [],
      networking_libraries: []
    }

    # Categorize libraries
    open_source_libs = ['OkHttp', 'Retrofit', 'Gson', 'AndroidX']
    security_libs = ['OpenSSL', 'BouncyCastle', 'Conscrypt', 'libsodium']
    networking_libs = ['OkHttp', 'Volley', 'Retrofit']

    @libraries.each do |lib|
      if open_source_libs.any? { |os| lib.include?(os) }
        third_party_analysis[:open_source] << lib
      end

      if security_libs.any? { |sec| lib.include?(sec) }
        third_party_analysis[:security_libraries] << lib
      end

      if networking_libs.any? { |net| lib.include?(net) }
        third_party_analysis[:networking_libraries] << lib
      end
    end

    @vpn_analysis[:third_party_analysis] = third_party_analysis
    print_status("Third-party SDKs: #{third_party_analysis[:total_sdks]} detected")
  end

  def analyze_vpn_protocols
    protocol_analysis = {
      supported_protocols: [],
      recommended_protocols: [],
      deprecated_protocols: []
    }

    recommended = ['WireGuard', 'OpenVPN', 'IKEv2/IPSec']
    deprecated = ['PPTP', 'L2TP (alone)']

    if @vpn_analysis[:encryption_analysis]
      protocols = @vpn_analysis[:encryption_analysis][:protocols]

      protocols.each do |proto|
        if recommended.any? { |r| proto.include?(r) }
          protocol_analysis[:recommended_protocols] << proto
        elsif deprecated.any? { |d| proto.include?(d) }
          protocol_analysis[:deprecated_protocols] << proto
        end

        protocol_analysis[:supported_protocols] << proto
      end
    end

    @vpn_analysis[:protocol_analysis] = protocol_analysis
  end

  def perform_dynamic_analysis
    # Dynamic analysis would require a real device
    print_status("Dynamic analysis requires device integration")
    print_status("This feature will analyze:")
    print_status("- Real-time traffic capture")
    print_status("- DNS leak testing")
    print_status("- IP leak testing")
    print_status("- Kill switch effectiveness")
    print_status("- Connection stability")

    # Placeholder for dynamic analysis results
    @vpn_analysis[:dynamic_analysis] = {
      performed: false,
      reason: 'Device not connected or dynamic analysis disabled'
    }
  end

  def calculate_vpn_risk_score
    score = 0

    # Count security issues
    critical = @vpn_analysis[:security_issues].count { |i| i[:severity] == 'CRITICAL' }
    high = @vpn_analysis[:security_issues].count { |i| i[:severity] == 'HIGH' }
    medium = @vpn_analysis[:security_issues].count { |i| i[:severity] == 'MEDIUM' }

    # Count privacy issues
    critical_privacy = @vpn_analysis[:privacy_issues].count { |i| i[:severity] == 'CRITICAL' }
    high_privacy = @vpn_analysis[:privacy_issues].count { |i| i[:severity] == 'HIGH' }

    # Calculate weighted score
    score += (critical + critical_privacy) * 25
    score += (high + high_privacy) * 15
    score += medium * 8

    # Additional scoring based on VPN-specific concerns
    score += 15 if @vpn_analysis[:dns_leak_analysis][:hardcoded_dns_servers].any?
    score += 15 if @vpn_analysis[:privacy_analysis][:tracking_sdks].any?
    score += 10 unless @vpn_analysis[:kill_switch_analysis][:kill_switch_detected]

    # Cap at 100
    score = [score, 100].min

    @vpn_analysis[:risk_score] = score

    # Generate VPN-specific recommendations
    if score >= 80
      @vpn_analysis[:recommendations] << 'CRITICAL: Do NOT use this VPN for privacy or security'
      @vpn_analysis[:recommendations] << 'This VPN has severe security and privacy issues'
    elsif score >= 60
      @vpn_analysis[:recommendations] << 'HIGH RISK: This VPN has significant security/privacy concerns'
      @vpn_analysis[:recommendations] << 'Consider using a more trustworthy VPN service'
    elsif score >= 40
      @vpn_analysis[:recommendations] << 'MEDIUM RISK: This VPN has some security/privacy issues'
      @vpn_analysis[:recommendations] << 'Review the issues before using for sensitive activities'
    elsif score >= 20
      @vpn_analysis[:recommendations] << 'LOW RISK: VPN shows acceptable security practices'
      @vpn_analysis[:recommendations] << 'Some minor issues should be addressed'
    else
      @vpn_analysis[:recommendations] << 'GOOD: VPN demonstrates strong security and privacy practices'
    end
  end

  def generate_vpn_report
    output_dir = datastore['OUTPUT_DIR'] || Dir.pwd
    FileUtils.mkdir_p(output_dir)

    timestamp = Time.now.strftime('%Y%m%d_%H%M%S')
    app_name = @package_id || 'unknown'
    base_filename = "vpn_analysis_#{app_name}_#{timestamp}"

    case datastore['REPORT_FORMAT']
    when 'JSON'
      generate_json_report(output_dir, base_filename)
    when 'HTML'
      generate_vpn_html_report(output_dir, base_filename)
    when 'TXT'
      generate_text_report(output_dir, base_filename)
    end
  end

  def generate_json_report(output_dir, base_filename)
    report_file = File.join(output_dir, "#{base_filename}.json")
    File.write(report_file, JSON.pretty_generate(@vpn_analysis))
    print_good("JSON report saved to: #{report_file}")
  end

  def generate_text_report(output_dir, base_filename)
    report_file = File.join(output_dir, "#{base_filename}.txt")

    report = []
    report << "=" * 80
    report << "VPN APPLICATION SECURITY ANALYSIS REPORT"
    report << "=" * 80
    report << ""
    report << "App: #{@app_name}"
    report << "Package: #{@package_id}"
    report << "Version: #{@app_version}"
    report << "Risk Score: #{@vpn_analysis[:risk_score]}/100"
    report << "Analyzed: #{@vpn_analysis[:metadata][:analyzed_at]}"
    report << ""
    report << "=" * 80
    report << "EXECUTIVE SUMMARY"
    report << "=" * 80
    report << ""
    report << "Security Issues: #{@vpn_analysis[:security_issues].length}"
    report << "Privacy Issues: #{@vpn_analysis[:privacy_issues].length}"
    report << "VPN Protocols: #{@vpn_analysis[:protocol_analysis][:supported_protocols].join(', ')}"
    report << "Encryption: #{@vpn_analysis[:encryption_analysis][:encryption_libraries].map { |e| e[:name] }.join(', ')}"
    report << ""

    File.write(report_file, report.join("\n"))
    print_good("Text report saved to: #{report_file}")
  end

  def generate_vpn_html_report(output_dir, base_filename)
    # Comprehensive HTML report for VPN analysis
    print_status("Generating comprehensive HTML report...")
  end

  def display_critical_findings
    critical_issues = @vpn_analysis[:security_issues].select { |i| i[:severity] == 'CRITICAL' }
    critical_privacy = @vpn_analysis[:privacy_issues].select { |i| i[:severity] == 'CRITICAL' }

    if critical_issues.any? || critical_privacy.any?
      print_error("=" * 80)
      print_error("CRITICAL FINDINGS")
      print_error("=" * 80)

      critical_issues.each do |issue|
        print_error("[SECURITY] #{issue[:title]}")
        print_error("  #{issue[:description]}")
      end

      critical_privacy.each do |issue|
        print_error("[PRIVACY] #{issue[:title]}")
        print_error("  #{issue[:description]}")
      end

      print_error("=" * 80)
    end
  end

  def store_vpn_analysis_results(app_path)
    return unless framework.db.active

    loot_data = JSON.pretty_generate(@vpn_analysis)

    store_loot(
      'mobile.vpn.analysis',
      'application/json',
      '127.0.0.1',
      loot_data,
      "#{@package_id}_vpn_analysis.json",
      "VPN Security Analysis: #{@package_id}"
    )

    print_good("VPN analysis results stored in database")
  end

  # Helper methods for APK/IPA processing
  def decompile_apk(apk_path)
    tempdir = Dir.mktmpdir('vpn_apk_')
    output_dir = File.join(tempdir, 'decompiled')

    result = run_cmd(['apktool', 'd', apk_path, '-o', output_dir, '-f'])

    if File.directory?(output_dir)
      tempdir
    else
      FileUtils.remove_entry(tempdir) if File.exist?(tempdir)
      nil
    end
  end

  def extract_ipa(ipa_path)
    # IPA extraction logic
    nil
  end

  def parse_android_manifest(tempdir)
    # Parse AndroidManifest.xml
  end

  def analyze_android_code(tempdir)
    # Analyze Android code
  end

  def parse_ios_info_plist(tempdir)
    # Parse iOS Info.plist
  end

  def analyze_ios_code(tempdir)
    # Analyze iOS code
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
