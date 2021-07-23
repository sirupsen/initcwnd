require 'net/ping'
require 'packetfu'
require 'uri'
require 'csv'
begin
  require 'byebug'
rescue LoadError
end

uri = URI(ARGV[0])

ping_times = 20.times.map do
  before = Time.now
  ping = Net::Ping::TCP.new(uri.host, 80)
  ping.ping?
  Time.now - before
end

ping_times = ping_times - [ping_times.max] # remove crazy outlier

median = ping_times.sort[ping_times.size / 2]
avg = ping_times.sum / ping_times.size
var = ping_times.sum { |ping| (ping - avg) ** 2 } / ping_times.size
stddev = Math.sqrt(var)

if uri.scheme != "https"
  puts "Script only supports https, should be easy to make it use http though."
  exit 1
end

if stddev > median * 0.9
  puts "There's a _huge_ variance in the ping times to this server. This will make it very difficult to figure out the windows. Is your connection stable? Trying again might work."
  exit 1
end

puts "p50:    #{median * 1000}ms"
puts "avg:    #{avg * 1000}ms"
puts "var:    #{var * 1000}ms"
puts "stddev: #{stddev * 1000}ms"

File.delete("initcwnd.pcap") if File.exist?("initcwnd.pcap")

pid = fork do
  exec("tcpdump", "-P", "-i", "en0", "-w", "initcwnd.pcap", "host", uri.host, "and", "port", "443")
end

sleep(2) # TCPdump needs a moment to start

# TODO: Convert to Ruby with proper error handling, especially for redirects.
# The reason I didn't is because curl supports SSLKEYLOGFILE which is very
# convenient for Wireshark.
# TODO: We do not send --compressed
site_html = `SSLKEYLOGFILE=key.log curl --compressed -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36" --fail --http1.1 #{uri.to_s}`
unless $?.success?
  puts "CURL failed. Maybe the URL is a redirect?"
  exit 1
end

sleep(1) # TCPdump needs a moment to capture

Process.kill("SIGQUIT", pid)
Process.wait(pid)

include PacketFu
puts "ok on to reading.."

first_ts = nil
previous_ts = 0

states = []

initcwnd_low_count = 0
initcwnd_low_data = 0
initcwnd_mid_count = 0
initcwnd_mid_data = 0
total_time = nil

tls_start_ts = nil
tls_total_time = nil

data_done_ts = nil
total_packets = 0
biggest_packets = 0
data_initial_window = 0
ttfb_start = nil
first_data = nil
ttfb = nil

current_window = nil
windows = {}
window_ranges = {}

open_new_window = true

packets = PcapNG::File.new.readfile("initcwnd.pcap") do |block|
  packet = Packet.parse(block.data)
  timestamp = block.timestamp
  first_ts = previous_ts = timestamp unless first_ts

  who_sym = packet.tcp_dst == 443 ? :client : :server
  who = packet.tcp_dst == 443 ? "\x1b[33mCLIENT" : "\x1b[31mSERVER"

  type = []
  type << "SYN" if packet.tcp_flags.syn == 1
  type << "FIN" if packet.tcp_flags.fin == 1
  type << "ACK" if packet.tcp_flags.ack == 1
  type = type.join("+")

  rel_time = ((timestamp - first_ts)*1000).round(0)
  diff_time = ((timestamp - previous_ts)*1000).round(0)

  output = "#{who}: [#{rel_time}ms/#{diff_time}ms] #{type} #{packet.size} bytes\x1b[0m: "
  if packet.payload[0..3] == "\x16\x03\x01\x00"
    output << "TLS CLIENT, START HANDSHAKE"
    tls_start_ts = previous_ts # computation can take a bit. go from ack.
    states << "tls_CLIENT"
  end

  if packet.payload[0..3] == "\x16\x03\x03\x00"
    output << "TLS KEY EXCH"
    states << "tls_key_exh_#{who_sym}"
  end

  if packet.payload[0..5] == "\x14\x03\x03\x00\x01\x01"
    output << "TLS SERVER DONE"
    states << "tls_done_#{who_sym}"
  end

  if packet.payload[0..3] == "\x15\x03\x03\x00"
    output << "TLS TERMINATE"
    states << "tls_terminated"
  end

  if packet.tcp_flags.ack == 1 && who_sym == :server && states.include?("tls_data_client") && packet.tcp_flags.fin == 0 && packet.payload.bytesize == 0 && !states.include?("tls_terminated")
    ttfb_start = timestamp
  end

  if packet.tcp_flags.ack == 1 && who_sym == :server && states.include?("tls_data_client") && packet.tcp_flags.fin == 0 && packet.payload.bytesize > 0 && !states.include?("tls_terminated")
    window_idx = windows.size

    # If we already have a window, we might extend or narrow it depending on
    # what the timestamp diference is to the last packet.
    if current_window
      total_packets += 1

      # It seems like this might actually be the end of the window.
      # Narrow it to the last event.
      suspiciously_large_gap = (timestamp - previous_ts) > median/3 &&
        windows.fetch(window_idx, []).size > 1
      current_window = (current_window.first...previous_ts) if suspiciously_large_gap

      puts "SUSPICIOUSLY LARGE" if suspiciously_large_gap

      # Extend the window if gap is less than ~3ms
      maximum_allowed_gap = 0.003
      maximum_window = (current_window.first..current_window.last + stddev)
      suspiciously_small_gap = (timestamp - previous_ts) <= maximum_allowed_gap &&
        !current_window.cover?(timestamp) &&
        maximum_window.cover?(timestamp)


      current_window = (current_window.first..current_window.last + maximum_allowed_gap) if suspiciously_small_gap
      window_ranges[window_idx] = current_window
    end

    if current_window && current_window.cover?(timestamp)
      windows[window_idx] ||= []
      windows[window_idx] << block
      puts "WINDOW #{windows.size}"
    else
      first_data ||= timestamp
      ttfb ||= timestamp - ttfb_start if ttfb_start

      # First or new window
      current_window = (timestamp...(timestamp + median - stddev))
      windows[window_idx + 1] = [block]
      window_ranges[window_idx + 1] = current_window

      puts "WINDOW #{windows.size}"
    end
  end

  # if packet.tcp_flags.ack == 1 && who_sym == :server && states.include?("tls_data_client") && !states.include?("server_ack_client_http")
  #   output << "SERVER ACKED client HTTP"
  #   states << "server_ack_client_http"
  # end

  if packet.tcp_flags.ack == 1 && packet.tcp_flags.fin == 1
    output << "BYE BYE"
    data_done_ts = timestamp
    total_time = timestamp - first_ts
    states << "fin"
  end

  if packet.payload[0..2] == "\x17\x03\x03"
    output << "TLS DATA"

    unless tls_total_time
      puts "DONE TLS HANDSHAKE"
      # byebug unless tls_start_ts
      tls_total_time = timestamp - tls_start_ts
    end

    states << "tls_data_#{who_sym}"
  end

  puts output
  puts

  previous_ts = timestamp
end

def to_ms(seconds, round = 0)
  "#{(seconds * 1000).round(round)} ms"
end

puts "TCP CONGESTION WINDOW ANALYSIS FOR #{ARGV[0]}"
# TODO: If whole response was contained in one window, we can't really tell you
# what the initcwnd is.
data_time = data_done_ts - windows[1].first.timestamp
puts "RTT p50:    #{to_ms(median, 1)}"
puts "RTT avg:    #{to_ms(avg, 1)}"
puts "RTT var:    #{to_ms(var,1 )}"
puts "RTT stddev: #{to_ms(stddev, 1)}\n\n"

total_packet_size = windows.sum do |(window_idx, blocks)|
  packets = blocks.map { |block| Packet.parse(block.data) }
  packets.sum { |p| p.payload.bytesize }
end

puts "TOTAL UNENCRYPTED, UNCOMPRESSED SIZE (HTML): #{site_html.bytesize} bytes"
puts "TOTAL NETWORK SIZE (COMPRESSED & ENCRYPTED): #{total_packet_size} bytes"
puts "SERVER PROCESSING TIME: #{to_ms(ttfb || -1)}\n"
puts "TTFB: #{to_ms(first_data - first_ts)}"

puts "TOTAL PACKETS: #{total_packets}"
puts "TOTAL TIME: #{to_ms(total_time)}\n\n"

# puts "\nTLS TIME: #{tls_total_time}"
# puts "TLS EXPECTED TIME: #{avg * 2}"
# puts "TLS APPROX RTS: #{(tls_total_time/median)}\n\n"

puts "DATA TIME: #{to_ms(data_time)}"
puts "DATA ROUNDTRIPS: #{windows.size}"

csv = CSV.new(File.open("initcwnd.csv", "w"))
first_window_size_bytes = nil
first_window_size = nil
puts "\nDATA WINDOWS (NOT TLS):\n"
windows.each_with_index do |(window_idx, blocks), index|
  range = window_ranges[window_idx]
  packets = blocks.map { |block| Packet.parse(block.data) }

  window_size_bytes = packets.sum { |p| p.payload.bytesize }
  first_window_size_bytes ||= window_size_bytes
  first_window_size ||= packets.size

  perc_total = ((window_size_bytes.to_f / total_packet_size) * 100).round(2)
  puts "\tWINDOW #{index + 1}: #{packets.size} @ #{window_size_bytes} bytes (#{perc_total}% of total)"
  byebug unless range
  csv << [((range.first - first_ts) * 1000).round(0), packets.size]
end
csv.close

puts "\n\nWritten windows to initcwnd.csv"
system("gnuplot initcwnd.gnuplot")
puts "Written plot to initcwnd.png"

csv = CSV.new(File.open("initcwnds.csv", "a"))

if File.empty?("initcwnds.csv")
  csv << [
    "Site", "Windows", "Initcwnd packets",
    "Initcwnd size", "Total network size", "% in first RTT",
    "Total transfer time", "TTFB"
  ]
end

csv << [
  ARGV[0], windows.size, first_window_size,
  first_window_size_bytes, total_packet_size,
  (first_window_size_bytes.to_f / total_packet_size).round(1),
  total_time.round(2), ttfb
]

puts "Written stats to initcwnds.csv"

# puts "INITCWND, (median - stddev)..(median)"
# puts "#{initcwnd_low_count} \\ #{initcwnd_low_data}b"
# puts "#{initcwnd_mid_count} \\ #{initcwnd_mid_data}b"
