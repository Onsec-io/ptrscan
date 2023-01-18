# frozen_string_literal: true

def resolve_dns(dns_name)
  result = []
  Resolv::DNS.open do |dns|
    dns.getresources(dns_name, Resolv::DNS::Resource::IN::A).map { |x| result << x.address.to_s }
  end
  result
end

def resolve_reverse_dns(ip_addr, resolver1, resolver2)
  result = []
  resolver_wrapper(resolver1, ip_addr).each { |ptr| result << ptr }
  resolver_wrapper(resolver2, ip_addr).each { |ptr| result << ptr }
  result.uniq
end

def resolver_wrapper(resolver, ip_addr)
  result = []
  begin
    resolver.getnames(ip_addr).each { |ptr| result << ptr.to_s }
  rescue Resolv::ResolvError
  rescue => e
    puts e.inspect
  end

  result
end

def prepare_resolver_data
  ns_name_list = @ns_enums.map { |_, ns_enumerator| ns_enumerator.next }
  ns_name_list.map { |ns| @ip_enums[ns].next }
end
