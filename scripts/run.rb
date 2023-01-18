# frozen_string_literal: true

require 'resolv'
require 'public_suffix'
require 'csv'
require 'set'
require 'ipaddr'
require 'concurrent-ruby'

load '/opt/scripts/ThreadPool.rb'
load '/opt/scripts/import_export.rb'
load '/opt/scripts/resolv.rb'
load '/opt/scripts/ip.rb'
load '/opt/scripts/filter.rb'

puts %q(
MM"""""""`YM M""""""""M MM"""""""`MM
MM  mmmmm  M Mmmm  mmmM MM  mmmm,  M
M'        .M MMMM  MMMM M'        .M .d8888b. .d8888b. .d8888b. 88d888b.
MM  MMMMMMMM MMMM  MMMM MM  MMMb. "M Y8ooooo. 88'  `"" 88'  `88 88'  `88
MM  MMMMMMMM MMMM  MMMM MM  MMMMM  M       88 88.  ... 88.  .88 88    88
MM  MMMMMMMM MMMM  MMMM MM  MMMMM  M `88888P' `88888P' `88888P8 dP    dP
MMMMMMMMMMMM MMMMMMMMMM MMMMMMMMMMMM
                                                                   v 1.0
)

threads = ENV['X_THREADS'] || 10
ip_subnets = []
summary_ns_data = {}
output_data = Concurrent::Array.new
domains_to_match = Set.new

File.readlines('/opt/input/nmap_networks_v4.txt').each do |line|
  next if line.strip.match(/^(\s+|\t+)$/)
  next if line.strip.match(/^$/)
  next if line.strip.match(/^#/)
  next if IPAddr.new(line.strip).prefix < 19

  ip_subnets << line.strip
end

ip_total = ip_subnets.map { |subnet| IPAddr.new(subnet).to_range.count }.sum
puts "Threads: #{threads}"
puts "Found #{ip_subnets.count} subnets with #{ip_total} IP total."

# read & parse NS information from file. Scope CSV report script output
File.readlines('/opt/input/domain_ns_info.txt').each do |line|
  next if line.match(/(^$|^\s+$|^\t+$)/)

  ns_info = line.strip.split(',')
  l2_domain = ns_info[0].to_s.downcase
  domains_to_match.add(PublicSuffix.parse(l2_domain).sld)

  ns_info[1..].each do |ns|
    ns = ns.downcase.gsub(/[.]$/, '')
    summary_ns_data[ns] = [] if summary_ns_data[ns].nil?
    summary_ns_data[ns] << l2_domain
  end
end

# collecting & grouping NS servers data
puts
puts '--------------------- NS information: ---------------------'

domain_groups = summary_ns_data.values.uniq
resolv_data = {}
domain_groups.each do |d_group|
  group_name = d_group.join(',')
  puts "Domain group: #{group_name}"
  # summary_ns_data.select { |_, val| val == d_group }.keys.each do |ns|
  summary_ns_data.select { |_, val| val == d_group }.each_key do |ns|
    puts "\s\s\s\s#{ns}"
    resolve_dns(ns).each do |ip|
      puts "\t#{ip}"
      resolv_data[group_name] = {} if resolv_data[group_name].nil?
      resolv_data[group_name][ns] = [] if resolv_data[group_name][ns].nil?
      resolv_data[group_name][ns] << ip
    end
  end
  puts '-' * 59
end

# transfotm NS & IP arrays to cycles
@ns_enums = {}
resolv_data.each do |group_name, ns_data|
  @ns_enums[group_name] = ns_data.keys.cycle
end

@ip_enums = {}
resolv_data.each do |_group_name, ns_data|
  ns_data.each do |ns_server, ip_list|
    @ip_enums[ns_server] = ip_list.cycle
  end
end

puts
resolver1 = Resolv::DNS.new
ip_subnets.each do |ip_subnet|
  puts ">> Checking for #{ip_subnet}"
  with_pool(threads) do |pool|
    subnet_size = IPAddr.new(ip_subnet).to_range.count
    get_ip_from_subnet(ip_subnet).each_with_index do |ip_addr, i|
      resolver2 = Resolv::DNS.new(nameserver: prepare_resolver_data)

      pool.post do
        ptr_list = resolve_reverse_dns(ip_addr, resolver1, resolver2)
        if ptr_filter(ptr_list)
          output_data << {
            ip_int: ip_to_int(ip_addr),
            ip_addr: ip_addr,
            subnet: ip_subnet,
            PTR: ptr_list.join("\n"),
            matched: prt_match(domains_to_match.to_a, ptr_list)
          }
        end
        print "  ~#{i}/#{subnet_size}\r"
        trap 'SIGINT' do
          puts "\nExiting..."
          exit 130
        end
      end
    end
  end
end

if output_data.empty?
  puts 'No data was collected, check input'
  exit 1
end

output_data.sort_by! { |x| x[:ip_int] }
output_data.each { |x| x.delete(:ip_int) }
save_result_as_csv(output_data, '/opt/output/ptr_report.csv')

puts 'Done. Check output directory'
