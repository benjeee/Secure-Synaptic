#!/usr/bin/env ruby

# encoding: UTF-8

###############################################################################
# This script takes the final.json file and creates a simplified 
# final csv file that has records that have at least one CVE number. Records
# that are for other branches of Debian are also removed. 
###############################################################################

require 'pp'
require 'json'
require 'csv'

###############################################################################
# CREATE HASH FROM FILE
###############################################################################

if ARGV.size < 1
    puts "usage: infile [outfile]"
    exit
end

filename = ARGV[0]
outfile = ARGV[1] || 'type2.csv'

p "starting type2 preprocessing"

csv_text = File.open(filename, "r:UTF-8").read
encoding_options = {
    :invalid           => :replace,  # Replace invalid byte sequences
    :undef             => :replace,  # Replace anything not defined in ASCII
    :replace           => '',        # Use a blank for those replacements
    :universal_newline => true       # Always break lines with \n
}
csv_ascii = csv_text.encode(Encoding.find('ASCII'), encoding_options)
csv_ascii.insert(0, "package,associated_packages,version,urgency,previous_version,cve_list,comments\n")
csv = CSV.parse(csv_ascii, :headers=>true)

p 'finished encoding'
# records is an array of records represented as JSON
records = csv.map { |e| e.to_hash } # NOTE ruby versions under 2.1 require e.to_hash.  post 2 require e.to_h

hash = Hash.new{ |h, k| h[k] = Hash.new { |h, k| h[k] = {} } }

# populate hash where each key is a package name and
# it is mapped to a hash whose keys are version numbers
records.each { |record|
	
	package = record["package"]
	version = record["version"]
	urgency = record["urgency"]
	prev_ver = record["previous_version"]
	cve_list = record["cve_list"]
	comments = record["comments"]

	bundle = hash[package]

	bundle[version] = { "previous_version" => prev_ver, "urgency" => urgency, "cve_list" => cve_list, "comments" => comments }
}

###############################################################################
# CREATE CLEAN CSV
###############################################################################

CSV.open(outfile, "w+") do |csv| #open new file for write

	hash.each { |package, versions|

		versions.each { |version, record|
            csv << [package,version,record["previous_version"],record["cve_list"]]
		}

	}

end

p "finished type2 preprocessing --> #{outfile}"
