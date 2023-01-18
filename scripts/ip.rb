# frozen_string_literal: true

def get_ip_from_subnet(subnet)
  IPAddr.new(subnet).to_range.map(&:to_s)
end

def ip_to_int(ip)
  ipi = 0
  ip = ip.to_s if ip.instance_of?(IPAddr)
  ip.split('.').reverse.each_with_index { |v, i| ipi += 255**i * v.to_i }
  ipi
end
