#!/usr/bin/env ruby

=begin
	csv file
		package name, current version, vulnerability description, severity, and CVE#
=end

require 'json'

if ARGV.size < 1
    puts "usage: infile [outfile] [delimeter]"
    exit
end

filename = ARGV[0]
outfile = ARGV[1] || 'type1.csv'
delimeter = ARGV[2] || "\t"

main_hash = JSON.parse(File.read(filename))

p "starting type1 preprocessing"

open(outfile, 'w') do |file|
	main_hash.each do |package, pack_val|
		pack_val.each do |cve, cve_val|
			if cve.include? "CVE" then					# only considers CVEs; throws DLA, DSA, TEMP, etc.
			
				if cve_val['releases'].has_key?('wheezy') then
					if cve_val['releases']['wheezy']['status'] == "open" then
					
						if cve_val['description'] then 
							description = cve_val['description'].gsub(delimeter, "").gsub("\"", "") #remove quotes and the delimeter from description
						else 
							description = "" 
						end
			
						urgency = cve_val['releases']['wheezy']['urgency'].gsub("*","")
                        extra_info = cve_val['releases']['wheezy']['nodsa'] || ""

						file.puts package.to_s + delimeter + cve_val['releases']['wheezy']['repositories']['wheezy'] + 
                            delimeter + description + delimeter + urgency + delimeter + cve + delimeter + extra_info
					end
				end
			end
		end
	end
end

p "finished type1 preprocessing --> #{outfile}"
