#!/usr/bin/env ruby
##
# Mobile Security Lab - Private Web GUI
# Provides web interface for lab operations
##

require 'sinatra/base'
require 'sinatra/json'
require 'json'
require 'fileutils'
require 'securerandom'

class MobileSecurityLabServer < Sinatra::Base
  set :bind, '0.0.0.0'
  set :port, 4567
  set :public_folder, File.join(File.dirname(__FILE__), 'public')
  set :views, File.join(File.dirname(__FILE__), 'views')

  # Authentication (basic - enhance for production)
  LAB_PASSWORD = ENV['LAB_PASSWORD'] || 'change_me_in_production'

  helpers do
    def protected!
      return if authorized?
      headers['WWW-Authenticate'] = 'Basic realm="Mobile Security Lab"'
      halt 401, "Not authorized\n"
    end

    def authorized?
      @auth ||= Rack::Auth::Basic::Request.new(request.env)
      @auth.provided? && @auth.basic? && @auth.credentials && @auth.credentials[1] == LAB_PASSWORD
    end

    def format_risk_score(score)
      if score >= 75
        { level: 'critical', text: 'CRITICAL', color: '#dc3545' }
      elsif score >= 50
        { level: 'high', text: 'HIGH', color: '#fd7e14' }
      elsif score >= 25
        { level: 'medium', text: 'MEDIUM', color: '#ffc107' }
      else
        { level: 'low', text: 'LOW', color: '#28a745' }
      end
    end
  end

  # Authentication middleware
  before do
    protected! unless request.path_info == '/health' || request.path_info.start_with?('/public/')
  end

  # Home page
  get '/' do
    @stats = get_lab_statistics
    erb :index
  end

  # Health check (no auth required)
  get '/health' do
    json status: 'ok', timestamp: Time.now.to_s
  end

  # Analysis queue
  get '/queue' do
    @queue = get_analysis_queue
    erb :queue
  end

  # Start new analysis
  get '/analyze/new' do
    erb :analyze_new
  end

  post '/analyze/upload' do
    unless params[:file]
      return json error: 'No file uploaded'
    end

    file = params[:file]
    platform = params[:platform] || 'android'
    analysis_type = params[:analysis_type] || 'static'
    vpn_focus = params[:vpn_focus] == 'true'

    # Save uploaded file
    upload_dir = File.join('uploads', SecureRandom.uuid)
    FileUtils.mkdir_p(upload_dir)

    file_path = File.join(upload_dir, file[:filename])
    File.open(file_path, 'wb') do |f|
      f.write(file[:tempfile].read)
    end

    # Create analysis job
    job_id = SecureRandom.uuid
    job = {
      id: job_id,
      filename: file[:filename],
      file_path: file_path,
      platform: platform,
      analysis_type: analysis_type,
      vpn_focus: vpn_focus,
      status: 'queued',
      created_at: Time.now.to_s,
      progress: 0
    }

    save_job(job)

    # Queue analysis
    Thread.new do
      run_analysis(job)
    end

    json job_id: job_id, status: 'queued'
  end

  # Get analysis status
  get '/analyze/:id/status' do
    job_id = params[:id]
    job = load_job(job_id)

    if job
      json job
    else
      status 404
      json error: 'Job not found'
    end
  end

  # Get analysis results
  get '/analyze/:id/results' do
    job_id = params[:id]
    job = load_job(job_id)

    unless job
      status 404
      return json error: 'Job not found'
    end

    if job[:status] == 'completed' && job[:results_file]
      results = JSON.parse(File.read(job[:results_file]))
      @results = results
      @job = job
      erb :results
    else
      @job = job
      erb :analysis_pending
    end
  end

  # Download report
  get '/analyze/:id/download/:format' do
    job_id = params[:id]
    format = params[:format]

    job = load_job(job_id)
    unless job && job[:status] == 'completed'
      status 404
      return 'Report not found'
    end

    report_file = job[:results_file].gsub('.json', ".#{format}")

    if File.exist?(report_file)
      send_file report_file, filename: "#{job[:filename]}_report.#{format}"
    else
      status 404
      'Report format not available'
    end
  end

  # List all analyses
  get '/analyses' do
    @analyses = get_all_analyses
    erb :analyses_list
  end

  # VPN apps database
  get '/vpn-apps' do
    @vpn_apps = get_vpn_apps_database
    erb :vpn_apps
  end

  # Download VPN apps
  post '/vpn-apps/download' do
    region = params[:region] || 'us'
    platform = params[:platform] || 'android'
    max_apps = (params[:max_apps] || 10).to_i

    job_id = SecureRandom.uuid
    job = {
      id: job_id,
      type: 'vpn_download',
      region: region,
      platform: platform,
      max_apps: max_apps,
      status: 'running',
      created_at: Time.now.to_s
    }

    save_job(job)

    # Start download in background
    Thread.new do
      run_vpn_download(job)
    end

    json job_id: job_id, status: 'running'
  end

  # Connected devices
  get '/devices' do
    @android_devices = get_android_devices
    @ios_devices = get_ios_devices
    erb :devices
  end

  # System settings
  get '/settings' do
    @settings = load_settings
    erb :settings
  end

  post '/settings' do
    save_settings(params[:settings])
    redirect '/settings'
  end

  # API endpoints

  # API: Submit analysis
  post '/api/v1/analyze' do
    content_type :json

    unless params[:file]
      return json error: 'No file provided'
    end

    # Process similar to /analyze/upload
    # Return JSON response
    json status: 'submitted', job_id: SecureRandom.uuid
  end

  # API: Get results
  get '/api/v1/results/:id' do
    content_type :json

    job_id = params[:id]
    job = load_job(job_id)

    unless job
      status 404
      return json error: 'Not found'
    end

    if job[:results_file] && File.exist?(job[:results_file])
      results = JSON.parse(File.read(job[:results_file]))
      json results
    else
      json status: job[:status], progress: job[:progress]
    end
  end

  # Helper methods

  def get_lab_statistics
    analyses_dir = 'data/analyses'
    FileUtils.mkdir_p(analyses_dir)

    total_analyses = Dir.glob(File.join(analyses_dir, '*/job.json')).count
    completed = Dir.glob(File.join(analyses_dir, '*/job.json')).count { |f|
      job = JSON.parse(File.read(f), symbolize_names: true)
      job[:status] == 'completed'
    }

    {
      total_analyses: total_analyses,
      completed: completed,
      in_progress: total_analyses - completed,
      android_analyses: 0,
      ios_analyses: 0,
      vpn_apps_analyzed: 0
    }
  end

  def get_analysis_queue
    analyses_dir = 'data/analyses'
    FileUtils.mkdir_p(analyses_dir)

    queue = []

    Dir.glob(File.join(analyses_dir, '*/job.json')).each do |job_file|
      job = JSON.parse(File.read(job_file), symbolize_names: true)
      queue << job if job[:status] != 'completed'
    end

    queue.sort_by { |j| j[:created_at] }
  end

  def save_job(job)
    job_dir = File.join('data/analyses', job[:id])
    FileUtils.mkdir_p(job_dir)

    job_file = File.join(job_dir, 'job.json')
    File.write(job_file, JSON.pretty_generate(job))
  end

  def load_job(job_id)
    job_file = File.join('data/analyses', job_id, 'job.json')
    return nil unless File.exist?(job_file)

    JSON.parse(File.read(job_file), symbolize_names: true)
  end

  def update_job(job)
    save_job(job)
  end

  def run_analysis(job)
    job[:status] = 'running'
    job[:started_at] = Time.now.to_s
    job[:progress] = 10
    update_job(job)

    # Determine module to use
    module_path = case job[:analysis_type]
                 when 'static'
                   job[:platform] == 'android' ? 'modules/auxiliary/scanner/mobile/apk_analyzer.rb' : 'modules/auxiliary/scanner/mobile/ios_analyzer.rb'
                 when 'dynamic'
                   'modules/auxiliary/scanner/mobile/dynamic_analyzer.rb'
                 when 'vpn'
                   'modules/auxiliary/scanner/mobile/vpn_analyzer.rb'
                 end

    # Run MSF module
    output_dir = File.join('data/analyses', job[:id])
    FileUtils.mkdir_p(output_dir)

    job[:progress] = 30
    update_job(job)

    # Execute analysis (simplified - in production use MSF framework properly)
    cmd = [
      'msfconsole',
      '-q',
      '-x',
      "use #{module_path}; set APP_FILE #{job[:file_path]}; set OUTPUT_DIR #{output_dir}; run; exit"
    ]

    job[:progress] = 50
    update_job(job)

    # Simulate analysis
    sleep(5)

    job[:progress] = 90
    update_job(job)

    # Save results
    results_file = File.join(output_dir, 'results.json')
    job[:results_file] = results_file

    job[:status] = 'completed'
    job[:progress] = 100
    job[:completed_at] = Time.now.to_s
    update_job(job)

  rescue StandardError => e
    job[:status] = 'failed'
    job[:error] = e.message
    job[:failed_at] = Time.now.to_s
    update_job(job)
  end

  def get_all_analyses
    analyses_dir = 'data/analyses'
    FileUtils.mkdir_p(analyses_dir)

    analyses = []

    Dir.glob(File.join(analyses_dir, '*/job.json')).each do |job_file|
      job = JSON.parse(File.read(job_file), symbolize_names: true)
      analyses << job
    end

    analyses.sort_by { |a| a[:created_at] }.reverse
  end

  def get_vpn_apps_database
    [
      { name: 'NordVPN', platform: 'Android', package: 'com.nordvpn.android', category: 'Premium', analyzed: true },
      { name: 'ExpressVPN', platform: 'Android', package: 'com.expressvpn.vpn', category: 'Premium', analyzed: false },
      { name: 'ProtonVPN', platform: 'Android', package: 'ch.protonvpn.android', category: 'Freemium', analyzed: true }
    ]
  end

  def run_vpn_download(job)
    # Run VPN downloader script
    job[:status] = 'completed'
    update_job(job)
  end

  def get_android_devices
    output = `adb devices 2>/dev/null`
    devices = []

    if output
      output.lines.each do |line|
        next unless line.include?('device') && !line.include?('List of devices')

        device_id = line.split.first
        devices << {
          id: device_id,
          platform: 'Android',
          status: 'connected'
        }
      end
    end

    devices
  end

  def get_ios_devices
    output = `idevice_id -l 2>/dev/null`
    devices = []

    if output
      output.lines.each do |line|
        device_id = line.strip
        next if device_id.empty?

        devices << {
          id: device_id,
          platform: 'iOS',
          status: 'connected'
        }
      end
    end

    devices
  end

  def load_settings
    settings_file = 'data/settings.json'
    if File.exist?(settings_file)
      JSON.parse(File.read(settings_file), symbolize_names: true)
    else
      {
        lab_name: 'Mobile Security Lab',
        auto_analyze_vpn: true,
        enable_dynamic_analysis: false,
        max_concurrent_jobs: 2
      }
    end
  end

  def save_settings(settings)
    settings_file = 'data/settings.json'
    File.write(settings_file, JSON.pretty_generate(settings))
  end

  # Start server
  run! if app_file == $0
end
