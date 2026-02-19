# encoding: utf-8

require 'logstash/filters/base'
require 'logstash/namespace'
require 'pg'
require 'json'
require 'yaml'

class LogStash::Filters::PostgresCVE < LogStash::Filters::Base
  config_name 'postgrescve'
  config :host,     :validate => :string, :required => true
  config :port,     :validate => :number, :default => 5432
  config :user,     :validate => :string, :required => true
  config :password, :validate => :string, :required => true
  config :database, :validate => :string, :required => true

  public
  def register
    @cpes_availables = Hash.new
    set_db_session
  end

  public
  def set_db_session
    @conn = PG.connect(pg_conn_info)
  rescue => e
    @logger.error("[PostgresCVE][set_db_session] Connection error: #{e}")
  end

  public
  def filter(event)
    @logger.info '[PostgresCVE] filter: Input received.'

    input_event = event.to_hash
    input_event.delete('@timestamp')
    input_event.delete('@version')

    @logger.info("[PostgresCVE]: Clean input: #{input_event}")
    cpe = input_event['cpe']
    @logger.info "[PostgresCVE]: New cpe to be fetched: #{cpe}"
    cpe_p_v = get_prod_version(cpe)
    return if cpe_p_v.empty?

    @cpes_availables ||= {}
    if !(@cpes_availables.key? cpe)
      @cpes_availables[cpe] = []

      # Query DB for rows containing the vendor-product CPE substring
      db_response = database(cpe_p_v[0])
      without_versions = cpe_p_v[1].nil?

      cve_list = []
      # @logger.info("[PostgresCVE][Filter]: DB response: #{db_response}")
      db_response.each do |row|
        document = JSON.parse(row['data'])
        @logger.info("[PostgresCVE][Filter]: To find: #{cpe_p_v}")
        # @logger.info("[PostgresCVE][Filter]: In document: #{document}")
        # @logger.info("[PostgresCVE][Filter]: Without versions: #{without_versions}")
        cve_list += find_cpe(cpe_p_v, document, without_versions)
      end

      @logger.info("[PostgresCVE][Filter]: Cve list: #{cve_list}")
      cve_list.each do |cve|
        output_event = set_output_event(input_event, cve)
        yield output_event
        @cpes_availables[cpe].push(cve)
      end
      @logger.info("[PostgresCVE]: New cpe to be fetched: #{cpe}")
      @cpes_availables[cpe].each do |saved_cve|
        output_event = set_output_event(input_event, saved_cve)
        yield output_event
      end
    else

    end
    @logger.info("[PostgresCVE]: Ending [DEBUG][filter]")

    event.cancel
  end

  def pg_conn_info
    # @database = 'redborder'
    # @host = 'master.postgresql.service'
    # @password = 'n2w7o8GUdctxl2zWxkLLj6ryuO11Z433sNP8w294Ay7G7DQMybfaK8hXQ7v2lczcYQ8kbCRSZO5dsoV68XvTqsB5XqaPvGUELqxtB0KQpED29GLgAfERSPJ1mq7YCt68'
    # @port = 5432
    # @user = 'redborder'
    {
      dbname: @database,
      user: @user,
      password: @password,
      host: @host,
      port: @port
    }
  end

  def set_output_event(input_event, cve_info)
    @logger.info '[PostgresCVE][set_output_event]: Starting'

    @logger.info '[PostgresCVE][set_output_event]: Gathering output data'
    cve_info = {} unless cve_info.is_a?(Hash)
    output_hash = input_event.merge(cve_info)

    @logger.info '[PostgresCVE][set_output_event]: Building output event'
    output_hash.each do |k, v|
      begin
        out_event = LogStash::Event.new
        out_event.set(k.to_s, v.to_s)
        @logger.info "[PostgresCVE][set_output_event]: Set key=#{k}, value=#{v.inspect} in new event"
        out_event
      rescue StandardError => e
        @logger.warn "[PostgresCVE][set_output_event]: Failed to set key=#{k}, value=#{v.inspect} - #{e.message}"
        return nil
      end
    end
  end

  def get_prod_version(cpe_orig)
    return [] unless cpe_orig

    @logger.info("[PostgresCVE]: Starting [DEBUG][get_prod_version]")
    cpe_vendor_product_version = cpe_orig.match('cpe:2.3:a:') ? cpe_orig.split('cpe:2.3:a:')[-1] : cpe_orig
    result = []
    parts = cpe_vendor_product_version.split(':')
    result.push(parts[0..1].join(':'))
    result.push(parts[2]) if parts.length >= 3
    @logger.info("[PostgresCVE]: Ending [DEBUG][get_prod_version]")
    result
  end

  def version_converter(version)
    version_without_subreleases = version.to_s.split(/[^0-9\.]/)[0]
    version_without_subreleases ? version_without_subreleases.split('.').map(&:to_i) : nil
  end

  def compare_version(version1, version2)
    v1 = version_converter(version1)
    v2 = version_converter(version2)
    v1 <=> v2
  end

  def find_cpe(cpe, document, without_versions)
    # input:  string cpe as key and hash document as complex hash map.
    # output: array
    @logger.info '[PostgresCVE][Find cpe]: Starting'
    cves = [] # will be filled with hashes with cve info
    # @logger.debug("Document: #{document}")
    # @logger.debug("Document CVE: #{document['cve']}")
    # @logger.info("[PostgresCVE][Find cpe]: configurations: #{document['cve']['configurations']}")
    # @logger.debug("Document NODES FIRST: #{document['cve']['configurations'].first['nodes']}")
    configurations = document.dig('cve', 'configurations') || [] # CHECKED
    nodes = configurations.flat_map { |h| h['nodes'] || [] } || []
    @logger.error '[PostgresCVE][filter]: Nodes not present in cves' if nodes.empty?
    nodes.each do |node|
      @logger.debug("Node: #{node}")
      cves.push(get_cve_data(document)) if scroll_cpe_match(cpe, node['cpeMatch']&.to_a, without_versions)
      node['children']&.each do |child|
        cves.push(get_cve_data(document)) if scroll_cpe_match(cpe, child['cpeMatch'], without_versions)
      end
    end
    cves.uniq
  end

  def scroll_cpe_match(cpe, cpe_match, without_versions)
    @logger.info("[PostgresCVE]: Starting [DEBUG][scroll_cpe_match]")
    matched = cpe_match.any? do |elem|
      @logger.info("[PostgresCVE]: Starting [DEBUG][scroll_cpe_match]: criteria: #{elem['criteria']}")
      cpe_db = get_prod_version(elem['criteria'])
      if cpe[0] == cpe_db[0]
        if without_versions
          true
        else
          if cpe_db[1] != '*' && !cpe_db[1].nil?
            compare_version(cpe[1], cpe_db[1]) == 0
          elsif cpe_db[1] == '*'
            version_range(cpe, elem)
          else
            false
          end
        end
      else
        false
      end
    end
    @logger.info("[PostgresCVE]: Ending [DEBUG][scroll_cpe_match]")
    matched
  end

  def version_range(cpe, cpe_match_elem)
    @logger.info("[PostgresCVE]: Starting [DEBUG][version_range]")
    inside_range = false
    if cpe_match_elem.key?("versionEndExcluding")
      if cpe_match_elem.key?("versionStartIncluding")
        inside_range = compare_version(cpe[1], cpe_match_elem["versionStartIncluding"]) != -1 &&
                       compare_version(cpe[1], cpe_match_elem["versionEndExcluding"]) == -1
      elsif cpe_match_elem.key?("versionStartExcluding")
        inside_range = compare_version(cpe[1], cpe_match_elem["versionStartExcluding"]) == 1 &&
                       compare_version(cpe[1], cpe_match_elem["versionEndExcluding"]) == -1
      else
        inside_range = compare_version(cpe[1], cpe_match_elem["versionEndExcluding"]) == -1
      end
    end

    if cpe_match_elem.key?("versionEndIncluding")
      if cpe_match_elem.key?("versionStartIncluding")
        inside_range = compare_version(cpe[1], cpe_match_elem["versionStartIncluding"]) != -1 &&
                       compare_version(cpe[1], cpe_match_elem["versionEndIncluding"]) != 1
      elsif cpe_match_elem.key?("versionStartExcluding")
        inside_range = compare_version(cpe[1], cpe_match_elem["versionStartExcluding"]) == 1 &&
                       compare_version(cpe[1], cpe_match_elem["versionEndIncluding"]) != 1
      else
        inside_range = compare_version(cpe[1], cpe_match_elem["versionEndIncluding"]) != 1
      end
    end

    if cpe_match_elem.key?("versionStartExcluding") && !cpe_match_elem.key?("versionEndExcluding") && !cpe_match_elem.key?("versionEndIncluding")
      inside_range = compare_version(cpe[1], cpe_match_elem["versionStartExcluding"]) == -1
    elsif cpe_match_elem.key?("versionStartIncluding") && !cpe_match_elem.key?("versionEndExcluding") && !cpe_match_elem.key?("versionEndIncluding")
      inside_range = compare_version(cpe[1], cpe_match_elem["versionStartIncluding"]) != -1
    end

    if !cpe_match_elem.key?("versionStartExcluding") && !cpe_match_elem.key?("versionStartIncluding") &&
       !cpe_match_elem.key?("versionEndExcluding") && !cpe_match_elem.key?("versionEndIncluding")
      inside_range = true
    end
    @logger.info("[PostgresCVE]: Ending [DEBUG][version_range]")
    inside_range
  end

  def cvss3?(metrics)
    metrics.to_s.scan(/cvssMetricV3/).any?
  end

  def cvss2?(metrics)
    metrics.to_s.scan(/cvssMetricV2/).any?
  end

  def cvss3_key(metrics)
    # Key can be either 'cvssMetricV3' or 'cvssMetricV31' or similar
    metrics.keys.find { |k| k =~ /cvssMetricV3/ }
  end

  def get_cve_data(document)
    @logger.info '[PostgresCVE]: Starting [DEBUG][get_cve_data]'
    @logger.info '[PostgresCVE][get_cve_data]: Document: ' + document.to_s

    cve_extra = {
      id: nil,
      cve_info: nil,
      metric: 'none',
      score: nil,
      severity: 'unknown'
    }

    begin
      cve_id = document.dig('cve', 'id')
      cve_extra[:id] = cve_id
      cve_extra[:cve_info] = "https://nvd.nist.gov/vuln/detail/#{cve_id}"
    rescue => e
      @logger.warn "[PostgresCVE][get_cve_data]: Failed to get CVE ID - #{e.message}"
    end

    begin
      metrics = document.dig('cve', 'metrics') || {}

      # Find CVSSv3 key
      cvss3_key = metrics.keys.find { |k| k =~ /cvssMetricV3/ } rescue nil

      if cvss3_key
        @logger.info '[PostgresCVE][get_cve_data]: Version 3'
        cve_extra[:metric] = 'cvssV3'

        cvss3_data = metrics[cvss3_key]
        cvss3 = cvss3_data.is_a?(Array) ? cvss3_data.first : cvss3_data

        cve_extra[:score] = cvss3['impactScore'] rescue nil
        cve_extra[:severity] = cvss3.dig('cvssData', 'baseSeverity') rescue 'unknown'

      elsif metrics['cvssMetricV2']
        @logger.info '[PostgresCVE][get_cve_data]: Version 2'
        cve_extra[:metric] = 'cvssV2'

        cvss2_data = metrics['cvssMetricV2']
        cvss2 = cvss2_data.is_a?(Array) ? cvss2_data.first : cvss2_data

        cve_extra[:score] = cvss2['impactScore'] rescue nil
        cve_extra[:severity] = cvss2['baseSeverity'] || cvss2.dig('cvssData', 'baseSeverity') rescue 'unknown'

      else
        @logger.error '[PostgresCVE][get_cve_data]: CVSS Version N/A'
      end
    rescue => e
      @logger.error "[PostgresCVE][get_cve_data]: Failed to process metrics - #{e.message}"
    end

    @logger.info "[PostgresCVE]: CVE data gotten: #{cve_extra}"
    cve_extra
  end

  def database(cpe_vendor_product)
    @logger.info("[PostgresCVE][database] Quering: #{cpe_vendor_product}")
    sql = <<~SQL
      SELECT data FROM cves
      WHERE data::text ILIKE '%:a:#{cpe_vendor_product}:%'
      LIMIT 1000
    SQL

    # for example             select * from cves where data::text ilike '.*:a:nginx:nginx:.*' limit 1;
    # for example             select * from cves where data::text ilike '%cpe:2.3:a:eric_allman:sendmail:5.58%' limit 1;
    # metaesploitable example select * from cves where data::text ilike '%:a:mysql:mysql%' limit 1;
    # metaesploitable example select data from cves where data::text ilike '%mysql:mysql%' limit 1;

    result = @conn.exec(sql)
    result.to_a
  rescue StandardError => e
    @logger.error("[PostgresCVE][database] Query error: #{e}")
    []
  end
end

## Helpers for directly debugging in IRB:

# def debug
#   @cpes_availables = nil
#   event = {
#     "cpe": "cpe:2.3:a:unrealircd:unrealircd",
#     "scan_id": "9",
#     "scan_type": "2",
#     "name": "scanner",
#     "uuid": "8534becf-c628-4a9a-8e96-f5b75afcaf7e",
#     "campus": "",
#     "campus_uuid": "",
#     "deployment": "",
#     "deployment_uuid": "",
#     "zone": "",
#     "zone_uuid": "",
#     "market": "",
#     "market_uuid": "",
#     "floor": "",
#     "floor_uuid": "",
#     "ipv4": "10.1.32.81",
#     "timestamp": 1771410211,
#     "product": "UnrealIRCd",
#     "version": nil,
#     "servicename": nil,
#     "protocol": "tcp",
#     "port_state": "open",
#     "port": "6667"
#   }
#   filter event
# end

# class Hash
#   def cancel
#    puts "SIMULACRO: EVENT CANCELLED: "
#    self
#    puts "END SIMULACRO: EVENT CANCELLED: "
#   end
# end


# Simple Event class to simulate Logstash::Event
# class EventDebug
#   attr_accessor :fields, :metadata

#   def initialize(initial_fields = {})
#     @fields = initial_fields.dup
#     @metadata = {
#       "@timestamp" => Time.now.utc,
#       "@version" => "1"
#     }
#   end

#   def remove(key)
#     @fields.delete(key)
#   end

#   # Hash-like access
#   def [](key)
#     @fields[key]
#   end

#   def []=(key, value)
#     @fields[key] = value
#   end

#   # Logstash-style set/get methods
#   def set(key, value)
#     @fields[key] = value
#   end

#   def get(key)
#     @fields[key]
#   end

#   # Tag support
#   def tag(tag_name)
#     @fields["tags"] ||= []
#     @fields["tags"] << tag_name
#   end

#   # Return combined hash
#   def to_h
#     @metadata.merge(@fields)
#   end
# end

# Usage
# event = EventDebug.new
# event.set("message", "Hello CVE")
# event.set("severity", "high")
# event.tag("cve_import")

# puts event.to_h
