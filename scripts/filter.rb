# frozen_string_literal: true

def prt_match(domains_to_match, ptr_list)
  domains_to_match.each do |domain|
    next if ptr_list.select { |ptr| ptr.match(domain) }.empty?

    return true
  end
  false
end

def ptr_filter(data)
  return false if data.empty?
  return false if data.select { |ptr| ptr.match(/^\d+[-.]\d+[-.]\d+[-.]\d+[-.]/) }.count == data.count

  true
end
