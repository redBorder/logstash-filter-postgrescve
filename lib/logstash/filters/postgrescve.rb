# encoding: utf-8

require 'logstash/filters/base'
require 'logstash/namespace'
require 'pg'
require 'json'
require 'yaml'

class LogStash::Filters::PostgresCVE < LogStash::Filters::Base

  config_name 'postgrescve'

  config :database_yml_path, :validate => :string, :default => "/var/www/rb-rails/config/database.yml"

  public
  def register
    @cpes_availables = Hash.new
    set_db_session
  end

  public
  def set_db_session
    @conn = PG.connect(pg_conn_info)
  rescue => e
    logger.error("[PostgresCVE][set_db_session] Connection error: #{e}")
  end

  public
  def filter(event)
    input_event = event.to_hash
    input_event.delete('@timestamp')
    input_event.delete('@version')

    cpe_p_v = get_prod_version(input_event["cpe"])
    return unless cpe_p_v[0] # skip if no CPE

    if !@cpes_availables.has_key?(input_event["cpe"])
      @cpes_availables[input_event["cpe"]] = []

      # Query DB for rows containing the vendor-product CPE substring
      db_response = database(cpe_p_v[0])
      without_versions = cpe_p_v[1].nil?

      cve_list = []
      db_response.each do |row|
        document = JSON.parse(row['data'])
        cve_list += find_cpe(cpe_p_v, document, without_versions)
      end

      cve_list.each do |cve|
        output_event = set_output_event(input_event, cve)
        yield output_event
        @cpes_availables[input_event["cpe"]].push(cve)
      end
    else
      @cpes_availables[input_event["cpe"]].each do |saved_cve|
        output_event = set_output_event(input_event, saved_cve)
        yield output_event
      end
    end

    event.cancel
  end

  def pg_conn_info
    raise "Missing #{@database_yml_path}" unless File.exist?(@database_yml_path)

    config = YAML.load_file(@database_yml_path)
    env = config['production'] || config['development']
    raise 'Missing production or development section in database.yml' unless env

    {
      dbname: env['database'],
      user: env['username'] || 'postgres',
      password: env['password'] || '',
      host: env['host'] || 'localhost',
      port: env['port'] || 5432
    }
  end

  def set_output_event(input_event, cve)
    out_event = LogStash::Event.new
    input_event.each { |k, v| out_event.set(k, v) }
    cve.each { |k, v| out_event.set(k, v) }
    out_event.remove('@timestamp')
    out_event.remove('@version')
    out_event
  end

  def get_prod_version(cpe_orig)
    cpe_vendor_product_version = cpe_orig.match('cpe:2.3:a:') ? cpe_orig.split('cpe:2.3:a:')[-1] : cpe_orig
    result = []
    parts = cpe_vendor_product_version.split(':')
    result.push(parts[0..1].join(':'))
    result.push(parts[2]) if parts.length >= 3
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
    cves = []
    nodes = document.dig("configurations", "nodes") || []
    nodes.each do |node|
      if node.key?("cpe_match")
        cves.push(get_cve_data(document)) if scroll_cpe_match(cpe, node["cpe_match"], without_versions)
      end
      if node.key?("children")
        node["children"].each do |child|
          cves.push(get_cve_data(document)) if scroll_cpe_match(cpe, child["cpe_match"], without_versions)
        end
      end
    end
    cves.uniq
  end

  def scroll_cpe_match(cpe, cpe_match, without_versions)
    cpe_match.any? do |elem|
      cpe_db = get_prod_version(elem["cpe23Uri"])
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
  end

  def version_range(cpe, cpe_match_elem)
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

    inside_range
  end

  def get_cve_data(document)
    cve_extra = {}
    cve_extra["cve"] = document["cve"]["CVE_data_meta"]["ID"]
    if document["impact"].key?("baseMetricV3")
      cve_extra["score"] = document["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
      cve_extra["metric"] = "cvssV3"
      cve_extra["severity"] = document["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
    else
      cve_extra["score"] = document["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
      cve_extra["metric"] = "cvssV2"
      cve_extra["severity"] = document["impact"]["baseMetricV2"]["severity"]
    end
    cve_extra["cve_info"] = "https://nvd.nist.gov/vuln/detail/#{cve_extra['cve']}"
    cve_extra
  end

  def database(cpe_vendor_product)
    sql = <<~SQL
      SELECT * FROM cves
      WHERE data::text ILIKE '%:a:#{cpe_vendor_product}:%'
      LIMIT 1000
    SQL

    result = @conn.exec(sql)
    result.to_a
  rescue => e
    logger.error("[PostgresCVE][database] Query error: #{e}")
    []
  end

end
