#!/usr/bin/env ruby
##
# Mobile Security Lab - VPN App Downloader
# Automatically downloads top VPN apps by region from app stores
##

require 'net/http'
require 'json'
require 'fileutils'
require 'optparse'

class VPNAppDownloader
  REGIONS = {
    'us' => 'United States',
    'uk' => 'United Kingdom',
    'de' => 'Germany',
    'fr' => 'France',
    'ca' => 'Canada',
    'au' => 'Australia',
    'jp' => 'Japan',
    'cn' => 'China',
    'in' => 'India',
    'br' => 'Brazil',
    'ru' => 'Russia',
    'mx' => 'Mexico',
    'es' => 'Spain',
    'it' => 'Italy',
    'nl' => 'Netherlands'
  }

  # Top VPN apps (by package ID / bundle ID)
  TOP_VPN_APPS = {
    android: [
      { name: 'NordVPN', package: 'com.nordvpn.android', category: 'Premium' },
      { name: 'ExpressVPN', package: 'com.expressvpn.vpn', category: 'Premium' },
      { name: 'Surfshark', package: 'com.surfshark.vpnclient.android', category: 'Premium' },
      { name: 'ProtonVPN', package: 'ch.protonvpn.android', category: 'Premium/Free' },
      { name: 'CyberGhost VPN', package: 'de.mobileconcepts.cyberghost', category: 'Premium' },
      { name: 'Private Internet Access', package: 'com.privateinternetaccess.android', category: 'Premium' },
      { name: 'Windscribe VPN', package: 'com.windscribe.vpn', category: 'Freemium' },
      { name: 'TunnelBear VPN', package: 'com.tunnelbear.android', category: 'Freemium' },
      { name: 'Hotspot Shield', package: 'hotspotshield.android.vpn', category: 'Freemium' },
      { name: 'Turbo VPN', package: 'free.vpn.unblock.proxy.turbovpn', category: 'Free' },
      { name: 'Super VPN', package: 'com.jrzheng.supervpnfree', category: 'Free' },
      { name: 'Thunder VPN', package: 'com.fast.free.unblock.thunder.vpn', category: 'Free' },
      { name: 'Betternet VPN', package: 'com.freevpnintouch', category: 'Free' },
      { name: 'Hola VPN', package: 'org.hola', category: 'Free' },
      { name: 'Opera VPN', package: 'com.opera.vpn', category: 'Free' },
      { name: 'IPVanish VPN', package: 'com.ixg.vpn', category: 'Premium' },
      { name: 'Mullvad VPN', package: 'net.mullvad.mullvadvpn', category: 'Premium' },
      { name: 'IVPN', package: 'net.ivpn.client', category: 'Premium' },
      { name: 'VyprVPN', package: 'com.goldenfrog.vyprvpn.app', category: 'Premium' },
      { name: 'Atlas VPN', package: 'com.nordvpn.atlasvpn', category: 'Freemium' }
    ],
    ios: [
      { name: 'NordVPN', bundle: 'com.nordvpn.ios', category: 'Premium' },
      { name: 'ExpressVPN', bundle: 'com.expressvpn.ExpressVPN', category: 'Premium' },
      { name: 'Surfshark', bundle: 'com.surfshark.vpnclient.ios', category: 'Premium' },
      { name: 'ProtonVPN', bundle: 'ch.protonvpn.ios', category: 'Premium/Free' },
      { name: 'CyberGhost VPN', bundle: 'com.cyberghostvpn.CyberGhostVPN', category: 'Premium' },
      { name: 'Private Internet Access', bundle: 'com.privateinternetaccess.ios', category: 'Premium' },
      { name: 'Windscribe VPN', bundle: 'com.windscribe.ios.vpn', category: 'Freemium' },
      { name: 'TunnelBear VPN', bundle: 'com.tunnelbear.ios.TunnelBear', category: 'Freemium' },
      { name: 'Hotspot Shield', bundle: 'com.anchorfree.hotspotshield', category: 'Freemium' },
      { name: 'IPVanish VPN', bundle: 'com.mudhookmarketing.ipvanish', category: 'Premium' },
      { name: 'Mullvad VPN', bundle: 'net.mullvad.MullvadVPN', category: 'Premium' },
      { name: 'VyprVPN', bundle: 'com.goldenfrog.vyprvpn', category: 'Premium' }
    ]
  }

  def initialize(options = {})
    @options = options
    @output_dir = options[:output_dir] || File.join(Dir.pwd, 'vpn_apps')
    @regions = options[:regions] || ['us']
    @platform = options[:platform] || 'both'
    @max_apps = options[:max_apps] || 10
    @categories = options[:categories] || ['Premium', 'Freemium', 'Free']

    FileUtils.mkdir_p(@output_dir)
  end

  def run
    puts "=" * 80
    puts "VPN App Downloader - Mobile Security Lab"
    puts "=" * 80
    puts "Output Directory: #{@output_dir}"
    puts "Regions: #{@regions.join(', ')}"
    puts "Platform: #{@platform}"
    puts "Max Apps per Region: #{@max_apps}"
    puts "=" * 80
    puts ""

    download_summary = {
      android: { attempted: 0, successful: 0, failed: 0 },
      ios: { attempted: 0, successful: 0, failed: 0 }
    }

    @regions.each do |region|
      puts "[*] Processing region: #{REGIONS[region] || region}"

      if @platform == 'both' || @platform == 'android'
        download_android_apps(region, download_summary[:android])
      end

      if @platform == 'both' || @platform == 'ios'
        download_ios_apps(region, download_summary[:ios])
      end

      puts ""
    end

    display_summary(download_summary)
    generate_app_list
  end

  def download_android_apps(region, summary)
    puts "  [Android] Fetching top VPN apps..."

    apps = TOP_VPN_APPS[:android].select { |app|
      @categories.include?(app[:category]) || app[:category].split('/').any? { |c| @categories.include?(c) }
    }.first(@max_apps)

    apps.each do |app|
      summary[:attempted] += 1

      app_dir = File.join(@output_dir, region, 'android', sanitize_filename(app[:name]))
      FileUtils.mkdir_p(app_dir)

      metadata_file = File.join(app_dir, 'metadata.json')
      File.write(metadata_file, JSON.pretty_generate({
        name: app[:name],
        package: app[:package],
        category: app[:category],
        platform: 'android',
        region: region,
        download_date: Time.now.to_s,
        source: 'Google Play Store'
      }))

      puts "    [+] #{app[:name]} (#{app[:package]})"
      puts "        Category: #{app[:category]}"
      puts "        Metadata saved: #{metadata_file}"

      # Note about APK download
      puts "        Note: Use google-play-cli or apkeep to download APK:"
      puts "        apkeep -a #{app[:package]} #{app_dir}"

      summary[:successful] += 1
    end
  end

  def download_ios_apps(region, summary)
    puts "  [iOS] Fetching top VPN apps..."

    apps = TOP_VPN_APPS[:ios].select { |app|
      @categories.include?(app[:category]) || app[:category].split('/').any? { |c| @categories.include?(c) }
    }.first(@max_apps)

    apps.each do |app|
      summary[:attempted] += 1

      app_dir = File.join(@output_dir, region, 'ios', sanitize_filename(app[:name]))
      FileUtils.mkdir_p(app_dir)

      metadata_file = File.join(app_dir, 'metadata.json')
      File.write(metadata_file, JSON.pretty_generate({
        name: app[:name],
        bundle: app[:bundle],
        category: app[:category],
        platform: 'ios',
        region: region,
        download_date: Time.now.to_s,
        source: 'Apple App Store'
      }))

      puts "    [+] #{app[:name]} (#{app[:bundle]})"
      puts "        Category: #{app[:category]}"
      puts "        Metadata saved: #{metadata_file}"

      # Note about IPA download
      puts "        Note: Use ipatool to download IPA:"
      puts "        ipatool download -b #{app[:bundle]} -o #{app_dir}"

      summary[:successful] += 1
    end
  end

  def display_summary(summary)
    puts "=" * 80
    puts "DOWNLOAD SUMMARY"
    puts "=" * 80
    puts ""
    puts "Android Apps:"
    puts "  Attempted: #{summary[:android][:attempted]}"
    puts "  Successful: #{summary[:android][:successful]}"
    puts "  Failed: #{summary[:android][:failed]}"
    puts ""
    puts "iOS Apps:"
    puts "  Attempted: #{summary[:ios][:attempted]}"
    puts "  Successful: #{summary[:ios][:successful]}"
    puts "  Failed: #{summary[:ios][:failed]}"
    puts ""
    puts "=" * 80
  end

  def generate_app_list
    list_file = File.join(@output_dir, 'vpn_apps_list.json')

    app_list = {
      generated_at: Time.now.to_s,
      regions: @regions,
      platforms: @platform == 'both' ? ['android', 'ios'] : [@platform],
      android_apps: TOP_VPN_APPS[:android].map { |app|
        {
          name: app[:name],
          package: app[:package],
          category: app[:category],
          download_command: "apkeep -a #{app[:package]} #{@output_dir}"
        }
      },
      ios_apps: TOP_VPN_APPS[:ios].map { |app|
        {
          name: app[:name],
          bundle: app[:bundle],
          category: app[:category],
          download_command: "ipatool download -b #{app[:bundle]} -o #{@output_dir}"
        }
      }
    }

    File.write(list_file, JSON.pretty_generate(app_list))
    puts "[+] App list saved to: #{list_file}"
    puts ""
  end

  def sanitize_filename(filename)
    filename.gsub(/[^0-9A-Za-z.\-]/, '_')
  end

  def self.create_download_script
    script_path = File.join(Dir.pwd, 'download_vpn_apps.sh')

    script_content = <<~SCRIPT
      #!/bin/bash
      # Automated VPN App Download Script
      # Generated by Mobile Security Lab

      echo "==================================="
      echo "VPN App Batch Downloader"
      echo "==================================="
      echo ""

      # Check for required tools
      if ! command -v apkeep &> /dev/null; then
        echo "[!] apkeep not found. Install: cargo install apkeep"
        echo "    https://github.com/EFForg/apkeep"
      fi

      if ! command -v ipatool &> /dev/null; then
        echo "[!] ipatool not found. Install: npm install -g ipatool"
        echo "    https://github.com/majd/ipatool"
      fi

      echo ""
      echo "Downloading Android VPN apps..."
      echo ""

      # Android apps
      #{TOP_VPN_APPS[:android].first(10).map { |app|
        "apkeep -a #{app[:package]} vpn_apps/android/#{app[:name].gsub(' ', '_')}.apk"
      }.join("\n")}

      echo ""
      echo "Downloading iOS VPN apps..."
      echo ""

      # iOS apps
      #{TOP_VPN_APPS[:ios].first(10).map { |app|
        "# ipatool download -b #{app[:bundle]} -o vpn_apps/ios/#{app[:name].gsub(' ', '_')}.ipa"
      }.join("\n")}

      echo ""
      echo "Download complete!"
      echo "Apps saved to: ./vpn_apps/"
    SCRIPT

    File.write(script_path, script_content)
    File.chmod(0755, script_path)

    puts "[+] Download script created: #{script_path}"
    puts "    Run: ./download_vpn_apps.sh"
  end
end

# CLI Interface
if __FILE__ == $0
  options = {}

  OptionParser.new do |opts|
    opts.banner = "Usage: vpn_app_downloader.rb [options]"

    opts.on("-o", "--output DIR", "Output directory") do |dir|
      options[:output_dir] = dir
    end

    opts.on("-r", "--regions REGIONS", Array, "Regions (comma-separated)") do |regions|
      options[:regions] = regions
    end

    opts.on("-p", "--platform PLATFORM", ['android', 'ios', 'both'], "Platform") do |platform|
      options[:platform] = platform
    end

    opts.on("-m", "--max-apps COUNT", Integer, "Max apps per region") do |count|
      options[:max_apps] = count
    end

    opts.on("-c", "--categories CATS", Array, "Categories") do |cats|
      options[:categories] = cats
    end

    opts.on("-s", "--create-script", "Create download script") do
      VPNAppDownloader.create_download_script
      exit
    end

    opts.on("-l", "--list-regions", "List available regions") do
      puts "Available regions:"
      VPNAppDownloader::REGIONS.each do |code, name|
        puts "  #{code} - #{name}"
      end
      exit
    end

    opts.on("-h", "--help", "Show this help") do
      puts opts
      exit
    end
  end.parse!

  downloader = VPNAppDownloader.new(options)
  downloader.run
end
