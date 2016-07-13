#!/usr/bin/env ruby

=begin
Notes about how this script works.  it combines 3 files into the final security bundle.
NVD datasource: cvss score / description of almost all CVEs.  fallback to type1 datasource otherwise
type1 datasource: in general this is the debian security tracker.  contains packages and CVE#s that affect them, and descriptions for the CVEs
type2 datasource: this contains information regarding which CVEs were patched at which version number of a package. It also contains the prev_version for each verversions: this is part of the whole curveball that nobody saw coming.  From the type2 datasource, at least in the way we received it, it is impossible to tell which was the latest version, and also which versions are part of debian wheezy. we need to use this file to figure out which was the latest version and then use the type2 datasource to create a path of current version-->first version.  This is important for the risk scoring algorithm.

In general the steps for the entire process are as follows:
1. create the map of data from nvd { CVE --> CVE_DATA}
2. initialize an empty map, bundles, to contain the security bundles after all processing is finished
3. add all of the current vulnerabilities from type1 datasource into the map (using data from nvd, but fallback on type1 if nvd does not have it)
4. add all of the patches for all versions from type2 to bundles (along with their cvss)
5. Now the hard part.  In order to give an overall risk score for each version, we need to take the max of the cvss's affecting a version number.  A vulnerability is said to affect a version if it is patched in a later version, or if it is known to exist in any later version. Figuring out the order of versions is going to be fun


=end
require 'json'
require 'csv'

if ARGV.size < 3
    puts "usage: type1_csv type2_csv nvd_csv [outfile]"
    exit
end

type1_filename = ARGV[0]
type2_filename = ARGV[1]
nvd_csv = ARGV[2]
outfile = ARGV[3] || "security_bundles.json"

nvd_data = {}
# format for type3 is: cve#, CVSS score, description,
CSV.foreach(nvd_csv, encoding: "utf-8", :col_sep => "\t") do |row|
    cve  = row[0].strip
    cvss = row[1].strip.to_f
    desc = row[2].strip

    nvd_data[cve] = {:cve => cve, :cvss => cvss, :description => desc}
end

p "done processing nvd"

bundles = {} # security bundles map for final json output
# format for type1: package name, current version, vulnerability description, severity, CVE#, extra_data (nodsa) if available
CSV.foreach(type1_filename, encoding: "utf-8",:col_sep => "\t") do |row| # note col_sep = delimeter

    pkgname  = row[0]
    ver      = row[1]
    desc     = row[2] || "N/A"
    severity = row[3]
    cve      = row[4].strip
    extra_info = row[5] || ""

    bundles[pkgname] ||= {}
    bundles[pkgname][:vulnerabilities] ||= []
    if nvd_data[cve].nil?
        bundles[pkgname][:vulnerabilities] << {:cve => cve, :cvss => 0, :description => desc, :extra_info => extra_info}
    else 
        nvd_data[cve][:extra_info] = extra_info
        bundles[pkgname][:vulnerabilities] << nvd_data[cve]
    end
end

p "done processing type1"

# this is the patch/version information
# format for type2 is: pkg, , description,
CSV.foreach(type2_filename, encoding: "utf-8") do |row|
    pkgname  = row[0].strip
    v_patched = row[1].strip
    prev_ver  = (row[2].nil?)? nil : row[2].strip
    cves_patched = if row[3].nil? then [] else row[3].strip.split(';') end

    bundles[pkgname] ||= {}
    bundles[pkgname][v_patched] = {
        :patches => cves_patched.map { |cve| 
            if nvd_data[cve].nil? then {:cve => cve, :cvss => 0, :description => "N/A"}
            else nvd_data[cve] end
        },
        :prev_v => prev_ver
    }
end

p "done processing type2"

CSV.foreach('versions.csv', encoding: "utf-8") do |row|
   pkgname = row[2].strip
   ver = row[3].strip
   next if bundles[pkgname].nil?

   v_order = [ver]
   until bundles[pkgname][ver].nil? 
    ver = bundles[pkgname][ver][:prev_v]
    break if v_order.include?(ver)
    v_order << ver
   end
   bundles[pkgname][:v_order] = v_order
end

p "done processing versions"

# lastly need to assign a risk to each version of each package
bundles.keys.each do |pkgname|
    if bundles[pkgname][:vulnerabilities].nil?
        latest_v_max = 0
    else 
        latest_v_max = bundles[pkgname][:vulnerabilities].map{ |vul| vul[:cvss] }.max # the greatest cvss num in current vuls 
    end
    max_stack = [latest_v_max] # to contain all cvss scores
    v_order = bundles[pkgname][:v_order]
    if ! v_order.nil? &&  !bundles[pkgname][v_order.first].nil?

        v_order.each_with_index do |ver, i|
            break if bundles[pkgname][v_order[i]].nil? # this usually will be nil for the last version
            bundles[pkgname][v_order[i]][:risk] = max_stack.max
            unless bundles[pkgname][ver][:patches].nil? || bundles[pkgname][ver][:patches].empty?
                max_in_v = bundles[pkgname][ver][:patches].map { |vul| vul[:cvss] }.max
                max_stack << max_in_v
            end
        end
    end
    # remove all empty versions now that risk has been assigned
    bundles[pkgname].delete_if do |key, v| 
        key != :vulnerabilities && key != :v_order && (v[:patches].nil? || v[:patches].empty? ||
             ! bundles[pkgname][:v_order].include?(key) )
    end
end

p "done assigning final risk scores to pkg versions"

File.open(outfile, 'w') do |f|
    f.write(JSON.pretty_generate(bundles))
end
