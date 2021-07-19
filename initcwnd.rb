require 'net/ping'
require 'packetfu'
require 'uri'
begin
  require 'byebug'
rescue LoadError
end

uri = URI("https://www.berlingske.dk/")

ping_times = 20.times.map do
  before = Time.now
  ping = Net::Ping::TCP.new(uri.host, 80)
  ping.ping?
  Time.now - before
end

median = ping_times.sort[ping_times.size / 2]
avg = ping_times.sum / ping_times.size
var = ping_times.sum { |ping| (ping - avg) ** 2 } / ping_times.size
stddev = Math.sqrt(var)

puts "p50:    #{median * 1000}ms"
puts "avg:    #{avg * 1000}ms"
puts "var:    #{var * 1000}ms"
puts "stddev: #{stddev * 1000}ms"

File.delete("initcwnd.pcap") if File.exist?("initcwnd.pcap")

pid = fork do
  exec("tcpdump", "-P", "-i", "en0", "-w", "initcwnd.pcap", "host", uri.host, "and", "port", "443")
end

sleep(1) # TCPdump needs a moment to start

# TODO: Convert to Ruby
site_html = `SSLKEYLOGFILE=key.log curl --http1.1 #{uri.to_s}`

sleep(1) # TCPdump needs a moment to capture

Process.kill("SIGQUIT", pid)
Process.wait(pid)

include PacketFu
puts "ok on to reading.."

first_ts = nil
previous_ts = 0

states = []

initcwnd_window_ts_start = nil
initcwnd_low_count = 0
initcwnd_low_data = 0
initcwnd_mid_count = 0
initcwnd_mid_data = 0
total_time = nil

tls_start_ts = nil
tls_total_time = nil

data_done_ts = nil
total_packets = 0
suspiciously_large_gap = false
biggest_packets = 0
data_initial_window = 0

windows = [
]

window_beginning_ts = [
]

window_open = true

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
    output << "TLS CLIENT"
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

  if packet.tcp_flags.ack == 1 && who_sym == :server && states.include?("tls_data_client") && packet.tcp_flags.fin == 0
    if packet.payload[0..2] == "\x17\x03\x03" && !initcwnd_window_ts_start
      puts "BEGINNING OF WINDOW"
      initcwnd_window_ts_start = timestamp
    end


    if initcwnd_window_ts_start
      total_packets += 1
      rel_window_duration = timestamp - initcwnd_window_ts_start

      suspiciously_large_gap ||= (timestamp - previous_ts) > (median/100)*30 && initcwnd_low_count > 2
      suspiciously_large_gap = false if initcwnd_window_ts_start == timestamp

      biggest_packets = [packet.payload.bytesize, biggest_packets].max

      if !suspiciously_large_gap
        # TODO: provide the range
        # TODO: provide a histogram, repeat the test
        if rel_window_duration < median - stddev
          puts "Counted: #{rel_window_duration} < #{median}"
          initcwnd_low_data += packet.payload.bytesize
          initcwnd_low_count += 1
        end

        if rel_window_duration < median
          initcwnd_mid_data += packet.payload.bytesize
          initcwnd_mid_count += 1
        end
      end
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
      tls_total_time = timestamp - tls_start_ts
    end

    states << "tls_data_#{who_sym}"
  end

  puts output
  puts

  previous_ts = timestamp
end

# TODO: If whole response was contained in one window, we can't really tell you
# what the initcwnd is.
data_time = data_done_ts - initcwnd_window_ts_start
puts "RTT p50:    #{median * 1000}ms"
puts "RTT avg:    #{avg * 1000}ms"
puts "RTT var:    #{var * 1000}ms"
puts "RTT stddev: #{stddev * 1000}ms\n"
puts "SIZE: #{site_html.bytesize}"
puts "TOTAL PACKETS: #{total_packets}"
puts "PACKET SIZE W DATA: #{biggest_packets}"
puts "TOTAL TIME: #{total_time}s"
puts "TOTAL APPROX RTS: #{(total_time/median)}"
puts "TLS TIME: #{tls_total_time}"
puts "TLS APPROX RTS: #{(tls_total_time/median)}"
puts "DATA TIME: #{data_time}s"
puts "DATA APPROX RTS: #{(data_time/median)}"
puts "INITCWND, (median - stddev)..(median)"
puts "#{initcwnd_low_count} \\ #{initcwnd_low_data}b"
puts "#{initcwnd_mid_count} \\ #{initcwnd_mid_data}b"
