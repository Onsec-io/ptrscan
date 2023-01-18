# frozen_string_literal: true

def save_result_as_csv(data, file_path)
  csv_data = CSV.generate(col_sep: "\t") do |csv|
    csv << data.first.keys.map(&:upcase)
    data.each { |element| csv << element.values }
  end

  File.open(file_path, 'w') { |file| file.write(csv_data) }
end
