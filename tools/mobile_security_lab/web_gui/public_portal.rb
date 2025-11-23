#!/usr/bin/env ruby
##
# Mobile Security Lab - Public Report Portal
# Read-only public access to analysis reports
##

require 'sinatra/base'
require 'sinatra/json'
require 'json'
require 'fileutils'

class PublicReportPortal < Sinatra::Base
  set :bind, '0.0.0.0'
  set :port, 8080
  set :public_folder, File.join(File.dirname(__FILE__), 'public')
  set :views, File.join(File.dirname(__FILE__), 'views/public')

  # Public site - no authentication required

  helpers do
    def format_risk_score(score)
      if score >= 75
        { level: 'critical', text: 'CRITICAL', color: '#dc3545', bg: '#fee' }
      elsif score >= 50
        { level: 'high', text: 'HIGH', color: '#fd7e14', bg: '#fff3cd' }
      elsif score >= 25
        { level: 'medium', text: 'MEDIUM', color: '#ffc107', bg: '#fff9e6' }
      else
        { level: 'low', text: 'LOW', color: '#28a745', bg: '#e8f5e9' }
      end
    end

    def format_timestamp(timestamp)
      Time.parse(timestamp).strftime('%Y-%m-%d %H:%M:%S') rescue timestamp
    end
  end

  # Homepage - List of reports
  get '/' do
    @reports = get_public_reports
    erb :public_index
  end

  # View specific report
  get '/report/:id' do
    report_id = params[:id]
    @report = load_public_report(report_id)

    unless @report
      status 404
      return erb :not_found
    end

    erb :public_report
  end

  # Download report (JSON)
  get '/report/:id/download' do
    report_id = params[:id]
    report = load_public_report(report_id)

    unless report
      status 404
      return 'Report not found'
    end

    content_type 'application/json'
    attachment "#{report_id}.json"
    JSON.pretty_generate(report)
  end

  # VPN leaderboard
  get '/vpn-leaderboard' do
    @leaderboard = get_vpn_leaderboard
    erb :vpn_leaderboard
  end

  # Statistics
  get '/statistics' do
    @stats = get_public_statistics
    erb :public_statistics
  end

  # API endpoints (read-only)

  # API: List reports
  get '/api/v1/reports' do
    content_type :json
    json reports: get_public_reports
  end

  # API: Get specific report
  get '/api/v1/reports/:id' do
    content_type :json

    report = load_public_report(params[:id])
    if report
      json report
    else
      status 404
      json error: 'Report not found'
    end
  end

  # API: VPN leaderboard
  get '/api/v1/vpn-leaderboard' do
    content_type :json
    json leaderboard: get_vpn_leaderboard
  end

  # Helper methods

  def get_public_reports
    reports_dir = 'data/public_reports'
    FileUtils.mkdir_p(reports_dir)

    reports = []

    Dir.glob(File.join(reports_dir, '*.json')).each do |report_file|
      report = JSON.parse(File.read(report_file), symbolize_names: true)
      reports << {
        id: File.basename(report_file, '.json'),
        app_name: report[:metadata][:filename] || 'Unknown',
        platform: report[:metadata][:app_type] || 'Unknown',
        risk_score: report[:risk_score] || 0,
        analyzed_at: report[:metadata][:analyzed_at],
        issues_count: (report[:security_issues]&.length || 0) + (report[:privacy_issues]&.length || 0)
      }
    end

    reports.sort_by { |r| r[:analyzed_at] }.reverse
  end

  def load_public_report(report_id)
    report_file = File.join('data/public_reports', "#{report_id}.json")
    return nil unless File.exist?(report_file)

    JSON.parse(File.read(report_file), symbolize_names: true)
  end

  def get_vpn_leaderboard
    reports = get_public_reports

    vpn_reports = reports.select { |r|
      r[:app_name].downcase.include?('vpn') rescue false
    }

    # Sort by risk score (lower is better)
    vpn_reports.sort_by { |r| r[:risk_score] }.map.with_index do |report, index|
      report.merge(rank: index + 1)
    end
  end

  def get_public_statistics
    reports = get_public_reports

    {
      total_reports: reports.length,
      android_reports: reports.count { |r| r[:platform] == 'android' },
      ios_reports: reports.count { |r| r[:platform] == 'ios' },
      critical_apps: reports.count { |r| r[:risk_score] >= 75 },
      vpn_apps_analyzed: reports.count { |r| r[:app_name].downcase.include?('vpn') rescue false },
      avg_risk_score: reports.any? ? (reports.sum { |r| r[:risk_score] } / reports.length).round(2) : 0
    }
  end

  # Start server
  run! if app_file == $0
end
