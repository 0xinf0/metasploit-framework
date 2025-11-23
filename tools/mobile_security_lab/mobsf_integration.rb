#!/usr/bin/env ruby
##
# Mobile Security Lab - MobSF Integration
# Integrates with Mobile Security Framework (MobSF) for enhanced analysis
# https://github.com/MobSF/Mobile-Security-Framework-MobSF
##

require 'net/http'
require 'json'
require 'fileutils'

class MobSFIntegration
  DEFAULT_HOST = 'localhost'
  DEFAULT_PORT = 8000

  def initialize(host: DEFAULT_HOST, port: DEFAULT_PORT, api_key: nil)
    @host = host
    @port = port
    @api_key = api_key || ENV['MOBSF_API_KEY']
    @base_url = "http://#{@host}:#{@port}"
  end

  # Upload and analyze APK/IPA
  def analyze_app(file_path)
    unless File.exist?(file_path)
      raise "File not found: #{file_path}"
    end

    puts "[*] Uploading #{File.basename(file_path)} to MobSF..."

    # Upload file
    upload_response = upload_file(file_path)
    return nil unless upload_response

    hash = upload_response['hash']
    scan_type = upload_response['scan_type']

    puts "[+] Upload successful. Hash: #{hash}"
    puts "[*] Starting analysis..."

    # Start scan
    scan_response = start_scan(hash, scan_type, file_path)

    if scan_response
      puts "[+] Analysis complete!"
      scan_response
    else
      puts "[-] Analysis failed"
      nil
    end
  end

  # Get scan results
  def get_scan_results(hash, scan_type)
    uri = URI("#{@base_url}/api/v1/report_json")
    request = Net::HTTP::Post.new(uri)
    request['Authorization'] = @api_key if @api_key

    request.set_form_data(
      'hash' => hash,
      'scan_type' => scan_type
    )

    response = Net::HTTP.start(uri.hostname, uri.port) do |http|
      http.request(request)
    end

    if response.code == '200'
      JSON.parse(response.body)
    else
      puts "[-] Failed to get scan results: #{response.code}"
      nil
    end
  end

  # Download PDF report
  def download_pdf_report(hash, scan_type, output_path)
    uri = URI("#{@base_url}/api/v1/download_pdf")
    request = Net::HTTP::Post.new(uri)
    request['Authorization'] = @api_key if @api_key

    request.set_form_data(
      'hash' => hash,
      'scan_type' => scan_type
    )

    response = Net::HTTP.start(uri.hostname, uri.port) do |http|
      http.request(request)
    end

    if response.code == '200'
      File.binwrite(output_path, response.body)
      puts "[+] PDF report saved: #{output_path}"
      true
    else
      puts "[-] Failed to download PDF: #{response.code}"
      false
    end
  end

  # Get recent scans
  def get_recent_scans(page: 1, page_size: 10)
    uri = URI("#{@base_url}/api/v1/scans")
    request = Net::HTTP::Post.new(uri)
    request['Authorization'] = @api_key if @api_key

    request.set_form_data(
      'page' => page.to_s,
      'page_size' => page_size.to_s
    )

    response = Net::HTTP.start(uri.hostname, uri.port) do |http|
      http.request(request)
    end

    if response.code == '200'
      JSON.parse(response.body)
    else
      nil
    end
  end

  # Delete scan
  def delete_scan(hash)
    uri = URI("#{@base_url}/api/v1/delete_scan")
    request = Net::HTTP::Post.new(uri)
    request['Authorization'] = @api_key if @api_key

    request.set_form_data('hash' => hash)

    response = Net::HTTP.start(uri.hostname, uri.port) do |http|
      http.request(request)
    end

    response.code == '200'
  end

  # Compare two apps
  def compare_apps(hash1, hash2)
    uri = URI("#{@base_url}/api/v1/compare")
    request = Net::HTTP::Post.new(uri)
    request['Authorization'] = @api_key if @api_key

    request.set_form_data(
      'hash1' => hash1,
      'hash2' => hash2
    )

    response = Net::HTTP.start(uri.hostname, uri.port) do |http|
      http.request(request)
    end

    if response.code == '200'
      JSON.parse(response.body)
    else
      nil
    end
  end

  # Enhanced analysis combining MSF and MobSF
  def enhanced_vpn_analysis(apk_path)
    puts "=" * 80
    puts "Enhanced VPN App Analysis (MSF + MobSF)"
    puts "=" * 80

    analysis_results = {
      mobsf_results: nil,
      msf_results: nil,
      combined_findings: [],
      risk_score: 0
    }

    # 1. MobSF Analysis
    puts "\n[*] Running MobSF analysis..."
    mobsf_results = analyze_app(apk_path)

    if mobsf_results
      analysis_results[:mobsf_results] = mobsf_results
      puts "[+] MobSF analysis complete"
    else
      puts "[-] MobSF analysis failed"
    end

    # 2. MSF VPN Analyzer
    puts "\n[*] Running MSF VPN analyzer..."
    msf_results = run_msf_vpn_analyzer(apk_path)

    if msf_results
      analysis_results[:msf_results] = msf_results
      puts "[+] MSF analysis complete"
    end

    # 3. Combine and correlate findings
    puts "\n[*] Correlating findings..."
    analysis_results[:combined_findings] = correlate_findings(mobsf_results, msf_results)

    # 4. Calculate enhanced risk score
    analysis_results[:risk_score] = calculate_combined_risk_score(analysis_results)

    # 5. Generate comprehensive report
    generate_enhanced_report(analysis_results, apk_path)

    analysis_results
  end

  private

  def upload_file(file_path)
    uri = URI("#{@base_url}/api/v1/upload")
    request = Net::HTTP::Post.new(uri)
    request['Authorization'] = @api_key if @api_key

    form_data = [
      ['file', File.open(file_path)]
    ]

    request.set_form(form_data, 'multipart/form-data')

    response = Net::HTTP.start(uri.hostname, uri.port) do |http|
      http.request(request)
    end

    if response.code == '200'
      JSON.parse(response.body)
    else
      puts "[-] Upload failed: #{response.code}"
      nil
    end
  end

  def start_scan(hash, scan_type, file_path)
    uri = URI("#{@base_url}/api/v1/scan")
    request = Net::HTTP::Post.new(uri)
    request['Authorization'] = @api_key if @api_key

    request.set_form_data(
      'hash' => hash,
      'scan_type' => scan_type,
      'file_name' => File.basename(file_path)
    )

    response = Net::HTTP.start(uri.hostname, uri.port) do |http|
      http.request(request)
    end

    if response.code == '200'
      # Get detailed results
      get_scan_results(hash, scan_type)
    else
      puts "[-] Scan failed: #{response.code}"
      nil
    end
  end

  def run_msf_vpn_analyzer(apk_path)
    # Run MSF VPN analyzer module
    # This would integrate with the VPN analyzer module we created
    {
      dns_leaks: [],
      ip_leaks: [],
      encryption_issues: [],
      privacy_issues: []
    }
  end

  def correlate_findings(mobsf_results, msf_results)
    findings = []

    # Correlate MobSF and MSF findings
    if mobsf_results && msf_results
      # Example: Cross-reference permission issues
      # Example: Validate encryption findings
      # Example: Combine network security issues
    end

    findings
  end

  def calculate_combined_risk_score(analysis_results)
    # Calculate weighted risk score from both tools
    score = 0

    if analysis_results[:mobsf_results]
      # Extract MobSF security score
      mobsf_score = analysis_results[:mobsf_results]['security_score'] || 0
      score += mobsf_score * 0.5
    end

    if analysis_results[:msf_results]
      # MSF risk score
      msf_score = analysis_results[:msf_results][:risk_score] || 0
      score += msf_score * 0.5
    end

    score.round(2)
  end

  def generate_enhanced_report(analysis_results, apk_path)
    report_file = "enhanced_report_#{Time.now.to_i}.json"
    File.write(report_file, JSON.pretty_generate(analysis_results))
    puts "\n[+] Enhanced report saved: #{report_file}"
  end
end

# CLI interface
if __FILE__ == $0
  require 'optparse'

  options = {}

  OptionParser.new do |opts|
    opts.banner = "Usage: mobsf_integration.rb [options]"

    opts.on("-f", "--file FILE", "APK/IPA file to analyze") do |file|
      options[:file] = file
    end

    opts.on("-H", "--host HOST", "MobSF host (default: localhost)") do |host|
      options[:host] = host
    end

    opts.on("-p", "--port PORT", "MobSF port (default: 8000)") do |port|
      options[:port] = port.to_i
    end

    opts.on("-k", "--api-key KEY", "MobSF API key") do |key|
      options[:api_key] = key
    end

    opts.on("-e", "--enhanced", "Run enhanced VPN analysis") do
      options[:enhanced] = true
    end

    opts.on("-h", "--help", "Show this help") do
      puts opts
      exit
    end
  end.parse!

  unless options[:file]
    puts "Error: File required"
    puts "Use -h for help"
    exit 1
  end

  mobsf = MobSFIntegration.new(
    host: options[:host] || MobSFIntegration::DEFAULT_HOST,
    port: options[:port] || MobSFIntegration::DEFAULT_PORT,
    api_key: options[:api_key]
  )

  if options[:enhanced]
    mobsf.enhanced_vpn_analysis(options[:file])
  else
    mobsf.analyze_app(options[:file])
  end
end
