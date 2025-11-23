#!/usr/bin/env ruby
##
# Standalone APK Analyzer Test - No MSF Dependencies
##

require 'json'
require 'digest'
require 'fileutils'

class StandaloneAPKAnalyzer
  def initialize(apk_path)
    @apk_path = apk_path
    @results = {
      metadata: {},
      analysis: {},
      errors: []
    }
  end

  def analyze
    puts "=" * 80
    puts "Standalone APK Analysis Test"
    puts "=" * 80
    puts "APK: #{File.basename(@apk_path)}"
    puts ""

    # Check file exists
    unless File.exist?(@apk_path)
      puts "❌ ERROR: File not found: #{@apk_path}"
      return false
    end

    # Basic metadata
    puts "[✓] Extracting metadata..."
    @results[:metadata] = {
      filename: File.basename(@apk_path),
      size: File.size(@apk_path),
      md5: Digest::MD5.file(@apk_path).hexdigest,
      sha256: Digest::SHA256.file(@apk_path).hexdigest
    }

    puts "    Size: #{@results[:metadata][:size]} bytes"
    puts "    MD5: #{@results[:metadata][:md5]}"
    puts "    SHA-256: #{@results[:metadata][:sha256]}"
    puts ""

    # Check for ZIP structure (APKs are ZIP files)
    puts "[*] Checking APK structure..."
    file_output = `file #{@apk_path} 2>&1`.strip

    if file_output.include?('Zip archive') || file_output.include?('Java archive')
      puts "    ✓ Valid ZIP/APK structure detected"
      @results[:analysis][:valid_structure] = true
    else
      puts "    ⚠ Warning: May not be a valid APK file"
      puts "    File type: #{file_output}"
      @results[:analysis][:valid_structure] = false
    end
    puts ""

    # Try to extract basic info with unzip -l
    puts "[*] Inspecting APK contents..."
    unzip_list = `unzip -l #{@apk_path} 2>&1`

    if $?.success?
      # Check for key APK components
      has_manifest = unzip_list.include?('AndroidManifest.xml')
      has_classes = unzip_list.include?('classes.dex')
      has_resources = unzip_list.include?('resources.arsc')
      has_meta_inf = unzip_list.include?('META-INF/')

      @results[:analysis][:components] = {
        has_manifest: has_manifest,
        has_dex: has_classes,
        has_resources: has_resources,
        has_signature: has_meta_inf
      }

      puts "    AndroidManifest.xml: #{has_manifest ? '✓' : '✗'}"
      puts "    classes.dex: #{has_classes ? '✓' : '✗'}"
      puts "    resources.arsc: #{has_resources ? '✓' : '✗'}"
      puts "    META-INF/ (signatures): #{has_meta_inf ? '✓' : '✗'}"

      if has_manifest && has_classes
        puts ""
        puts "    ✓ This appears to be a valid APK!"
      else
        puts ""
        puts "    ⚠ Missing critical APK components"
      end
    else
      puts "    ✗ Could not inspect APK contents"
      @results[:errors] << "Failed to list APK contents"
    end
    puts ""

    # Check for required analysis tools
    puts "[*] Checking analysis tools availability..."
    tools = {
      'apktool' => check_tool('apktool'),
      'aapt' => check_tool('aapt'),
      'keytool' => check_tool('keytool'),
      'apksigner' => check_tool('apksigner'),
      'zipalign' => check_tool('zipalign')
    }

    tools.each do |tool, available|
      status = available ? '✓' : '✗'
      puts "    #{status} #{tool}"
    end

    @results[:analysis][:tools_available] = tools
    puts ""

    # Summary
    puts "=" * 80
    puts "Analysis Summary"
    puts "=" * 80

    if @results[:analysis][:valid_structure] && @results[:analysis][:components][:has_manifest]
      puts "✓ Valid APK file detected"
      puts ""
      puts "Next steps:"
      if tools.values.all?
        puts "  ✓ All analysis tools available - ready for full analysis!"
        puts "  Run: msfconsole -q -x 'use auxiliary/scanner/mobile/apk_analyzer; set APK_FILE #{@apk_path}; run; exit'"
      else
        missing_tools = tools.select { |k, v| !v }.keys
        puts "  ⚠ Install missing tools: #{missing_tools.join(', ')}"
        puts "  See: tools/mobile_security_lab/README.md"
      end
    else
      puts "✗ Issues detected with APK file"
      puts "Errors: #{@results[:errors].join(', ')}" if @results[:errors].any?
    end
    puts ""

    # Save results
    report_file = "standalone_test_#{Time.now.to_i}.json"
    File.write(report_file, JSON.pretty_generate(@results))
    puts "Results saved: #{report_file}"
    puts "=" * 80

    true
  end

  private

  def check_tool(tool)
    `which #{tool} 2>/dev/null`.strip != ''
  end
end

# Main
if ARGV.empty?
  puts "Usage: #{$0} <path_to_apk>"
  puts ""
  puts "This is a standalone test to verify APK analysis capabilities"
  puts "without requiring full Metasploit Framework setup."
  exit 1
end

apk_path = ARGV[0]
analyzer = StandaloneAPKAnalyzer.new(apk_path)
analyzer.analyze
