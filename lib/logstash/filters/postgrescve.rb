# frozen_string_literal: true

require 'logstash/filters/base'
require 'logstash/namespace'
require 'pg'
require 'json'
require 'yaml'

module LogStash
  module Filters
    class PostgresCVE < LogStash::Filters::Base
      config_name 'postgrescve'
      config :host,     validate: :string, required: true
      config :port,     validate: :number, default: 5432
      config :user,     validate: :string, required: true
      config :password, validate: :string, required: true
      config :database, validate: :string, required: true

      def register
        @cpes_availables = {}
        set_db_session
      end

      def set_db_session
        @conn = PG.connect(pg_conn_info)
      rescue StandardError => e
        @logger.error("[PostgresCVE][set_db_session] Connection error: #{e}")
      end

      def filter(event)
        @logger.info '[PostgresCVE][filter]: Input received.'

        input_event = event.to_hash
        input_event.delete('@timestamp')
        input_event.delete('@version')

        cpe = input_event['cpe']
        cpe_p_v = get_prod_version(cpe)
        return event.cancel if cpe_p_v.empty?

        @cpes_availables ||= {}
        unless @cpes_availables.key? cpe
          @cpes_availables[cpe] = []

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
            @cpes_availables[cpe].push(cve)
          end
          @cpes_availables[cpe].each do |saved_cve|
            output_event = set_output_event(input_event, saved_cve)
            yield output_event
          end
        end
        event.cancel
      end

      def pg_conn_info
        {
          dbname: @database,
          user: @user,
          password: @password,
          host: @host,
          port: @port
        }
      end

      def set_output_event(input_event, cve_info)
        cve_info = {} unless cve_info.is_a?(Hash)
        output_hash = input_event.merge(cve_info)

        out_event = LogStash::Event.new
        output_hash.each do |k, v|
          out_event.set(k.to_s, v)
        rescue StandardError => e
          @logger.warn "[PostgresCVE][set_output_event]: Failed to set key=#{k}, value=#{v.inspect} - #{e.message}"
          return nil
        end
        @logger.info '[PostgresCVE][set_output_event]: SENDING EVENT'
        out_event
      end

      def get_prod_version(cpe_orig)
        return [] unless cpe_orig

        result = []
        cpe_vendor_product_version = cpe_orig.match('cpe:2.3:a:') ? cpe_orig.split('cpe:2.3:a:')[-1] : cpe_orig
        parts = cpe_vendor_product_version.split(':')
        result.push(parts[0..1].join(':'))
        result.push(parts[2]) if parts.length >= 3
        result
      end

      def version_converter(version)
        version_without_subreleases = version.to_s.split(/[^0-9.]/)[0]
        version_without_subreleases&.split('.')&.map(&:to_i)
      end

      def compare_version(version1, version2)
        v1 = version_converter(version1)
        v2 = version_converter(version2)
        v1 <=> v2
      end

      def find_cpe(cpe, document, without_versions)
        # input:  string cpe as key and hash document as complex hash map.
        # output: array
        cves = [] # will be filled with hashes with cve info
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
        matched = cpe_match.any? do |elem|
          cpe_db = get_prod_version(elem['criteria'])
          if cpe[0] == cpe_db[0]
            if without_versions
              true
            elsif cpe_db[1] != '*' && !cpe_db[1].nil?
              compare_version(cpe[1], cpe_db[1]).zero?
            elsif cpe_db[1] == '*'
              version_range(cpe, elem)
            else
              false
            end
          else
            false
          end
        end
        matched
      end

      def version_range(cpe, cpe_match_elem)
        inside_range = false
        if cpe_match_elem.key?('versionEndExcluding')
          inside_range = if cpe_match_elem.key?('versionStartIncluding')
                           compare_version(cpe[1], cpe_match_elem['versionStartIncluding']) != -1 &&
                             compare_version(cpe[1], cpe_match_elem['versionEndExcluding']) == -1
                         elsif cpe_match_elem.key?('versionStartExcluding')
                           compare_version(cpe[1], cpe_match_elem['versionStartExcluding']) == 1 &&
                             compare_version(cpe[1], cpe_match_elem['versionEndExcluding']) == -1
                         else
                           compare_version(cpe[1], cpe_match_elem['versionEndExcluding']) == -1
                         end
        end

        if cpe_match_elem.key?('versionEndIncluding')
          inside_range = if cpe_match_elem.key?('versionStartIncluding')
                           compare_version(cpe[1], cpe_match_elem['versionStartIncluding']) != -1 &&
                             compare_version(cpe[1], cpe_match_elem['versionEndIncluding']) != 1
                         elsif cpe_match_elem.key?('versionStartExcluding')
                           compare_version(cpe[1], cpe_match_elem['versionStartExcluding']) == 1 &&
                             compare_version(cpe[1], cpe_match_elem['versionEndIncluding']) != 1
                         else
                           compare_version(cpe[1], cpe_match_elem['versionEndIncluding']) != 1
                         end
        end

        if cpe_match_elem.key?('versionStartExcluding') && !cpe_match_elem.key?('versionEndExcluding') && !cpe_match_elem.key?('versionEndIncluding')
          inside_range = compare_version(cpe[1], cpe_match_elem['versionStartExcluding']) == -1
        elsif cpe_match_elem.key?('versionStartIncluding') && !cpe_match_elem.key?('versionEndExcluding') && !cpe_match_elem.key?('versionEndIncluding')
          inside_range = compare_version(cpe[1], cpe_match_elem['versionStartIncluding']) != -1
        end

        if !cpe_match_elem.key?('versionStartExcluding') && !cpe_match_elem.key?('versionStartIncluding') &&
           !cpe_match_elem.key?('versionEndExcluding') && !cpe_match_elem.key?('versionEndIncluding')
          inside_range = true
        end
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
        rescue StandardError => e
          @logger.error "[PostgresCVE][get_cve_data]: Failed to get CVE ID - #{e.message}"
        end

        begin
          metrics = document.dig('cve', 'metrics') || {}

          # Find CVSSv3 key
          cvss3_key = begin
            metrics.keys.find { |k| k =~ /cvssMetricV3/ }
          rescue StandardError
            nil
          end

          if cvss3_key
            cve_extra[:metric] = 'cvssV3'

            cvss3_data = metrics[cvss3_key]
            cvss3 = cvss3_data.is_a?(Array) ? cvss3_data.first : cvss3_data

            cve_extra[:score] = begin
              cvss3['impactScore']
            rescue StandardError
              nil
            end
            cve_extra[:severity] = begin
              cvss3.dig('cvssData', 'baseSeverity')
            rescue StandardError
              'unknown'
            end

          elsif metrics['cvssMetricV2']
            cve_extra[:metric] = 'cvssV2'

            cvss2_data = metrics['cvssMetricV2']
            cvss2 = cvss2_data.is_a?(Array) ? cvss2_data.first : cvss2_data

            cve_extra[:score] = begin
              cvss2['impactScore']
            rescue StandardError
              nil
            end
            cve_extra[:severity] = begin
              cvss2['baseSeverity'] || cvss2.dig('cvssData', 'baseSeverity')
            rescue StandardError
              'unknown'
            end

          else
            @logger.error '[PostgresCVE][get_cve_data]: CVSS Version N/A'
          end
        rescue StandardError => e
          @logger.error "[PostgresCVE][get_cve_data]: Failed to process metrics - #{e.message}"
        end

        @logger.info "[PostgresCVE]: CVE data gotten: #{cve_extra}"
        cve_extra
      end

      def database(cpe_vendor_product)
        sql = <<~SQL
          SELECT data FROM cves
          WHERE data::text ILIKE '%:a:#{cpe_vendor_product}:%'
          LIMIT 1;
        SQL

        result = @conn.exec(sql)
        result.to_a
      rescue StandardError => e
        @logger.error("[PostgresCVE][database] Query error: #{e}")
        []
      end
    end
  end
end
