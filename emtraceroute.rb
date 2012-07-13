#!/usr/bin/env ruby
# -*- coding: utf-8 -*-
require 'rubygems'
require 'socket'
require 'eventmachine'
require 'open-uri'
require 'json'
require 'optparse'

# version
Version = '0.0.1a'


# extension for socket library
class Socket
  def self.inet_aton ip
    ip.split(/\./).map(&:to_i).pack("C*")
  end

  def self.inet_ntoa n
    n.unpack("C*").join "."
  end

  def self.htons id
    [id].pack("s").unpack("n").first.to_i
  end
end


class Iphdr
  # This represents an IP packet header.
  #
  # Iphdr#assemble packages the packet
  # Iphdr.disassemble disassembles the packet
  #
  attr_accessor :version, :hlen, :tos, :id, :length, :frag,
   :ttl, :dst, :proto, :cksum, :src, :saddr, :daddr, :data
  def initialize(proto=Socket::IPPROTO_ICMP, src='0.0.0.0', dst=nil)
    @version = 4
    @hlen = 5
    @tos = 0
    @length = 20
    @id = $$
    @frag = 0
    @ttl = 255
    @proto = proto
    @cksum = 0
    @src = src
    @saddr = Socket.inet_aton(src)
    @dst = dst || '0.0.0.0'
    @daddr = Socket.inet_aton(@dst)
    @data = ''
  end

  def assemble
    header = [(@version & 0x0f) << 4 | (@hlen & 0x0f),
              @tos, @length + @data.size,
              Socket.htons(@id), @frag,
              @ttl, @proto
             ].pack('CCSSSCC')
    header + "\000\000" + @saddr.to_s + @daddr.to_s + @data
  end

  def self.disassemble data
    ip = Iphdr.new
    pkt = data[0..11].unpack('CCnnnCCn')
    ip.version = (pkt.first >> 4 & 0x0f)
    ip.hlen = (pkt.first & 0x0f)
    ip.tos, ip.length, ip.id, ip.frag, ip.ttl, ip.proto, ip.cksum = pkt[1..-1]
    ip.saddr = data[12..15]
    ip.daddr = data[16..19]
    ip.src = Socket.inet_ntoa(ip.saddr)
    ip.dst = Socket.inet_ntoa(ip.daddr)
    ip
  end
end


class Icmphdr
  attr_accessor :type, :code, :cksum, :id, :sequence, :data
  def initialize data=""
    @type = 8
    @code = 0
    @cksum = 0
    @id = $$
    @sequence = 0
    @data = data
  end

  def assemble
    part1 = [@type, @code].pack('C*')
    part2 = [@id, @sequence].pack('n*')
    cksum = Icmphdr.checksum(part1 + "\000\000" + part2 + @data)
    cksum = [cksum].pack('n')
    part1 + cksum + part2 + @data
  end

  def self.checksum data
    data += '\0' if data.size & 1 == 1

    cksum = data.unpack("n*")[0..(data.size >> 1)].inject(&:+)
    cksum = (cksum >> 16) + (cksum & 0xffff)
    cksum += (cksum >> 16)
    cksum = (cksum & 0xffff) ^ 0xffff
    cksum
  end

  def self.disassemble data
    icmp = Icmphdr.new
    pkt = data.unpack('CCnnn')
    icmp.type, icmp.code, icmp.cksum, icmp.id, icmp.sequence = pkt
    icmp
  end
end


class Hop
  attr_accessor :found, :tries, :remote_ip, :remote_icmp, :location,
  :ttl, :ip, :pkt, :icmp
  def initialize target, ttl
    @found = false
    @tries = 0
    @last_try = 0
    @remote_ip = nil
    @remote_icmp = nil
    @location = ""

    @ttl = ttl
    @ip = Iphdr.new(Socket::IPPROTO_ICMP, '0.0.0.0', target) # IP header
    @ip.ttl = ttl
    @ip.id += ttl

    @icmp = Icmphdr.new("traceroute") # ICMP header
    @icmp.id = @ip.id
    @ip.data = @icmp.assemble

    @pkt = @ip.assemble
  end

  def pkt
    @tries += 1
    @last_try = Time.now.to_f
    @pkt
  end

  def to_s
    if @found
      ip = ":: #{remote_ip.src}"
      ping = "#{(@found - @last_try).round(3)}s"
    else
      ip = "??"
      ping = "-"
    end

    location = ":: #{@location}" 
    "#{@ttl}. #{ping} #{ip} #{location}"
  end
end


module Handler
  attr_reader :deferred
  def initialize target, settings
    @target = target
    @settings = settings
  end

  def post_init
    @hops = []
    @out_queue = []
    @waiting = true

    @deferred = EM::DefaultDeferrable.new

    # send first probe packet
    @out_queue << Hop.new(@target, 1)
  end

  def notify_readable
    return if !@waiting || @hops.empty?

    pkt = @io.recv(4096)

    # disassemble ip header
    ip = Iphdr.disassemble(pkt[0..19])
    unless ip.proto != Socket::IPPROTO_ICMP

      found = false
      
      # disassemble icmp header
      icmp = Icmphdr.disassemble(pkt[20..27])
      if icmp.type == 0 && icmp.id == @hops.last.icmp.id
        found = true
      elsif icmp.type == 11
        # disassemble referenced ip header
        ref = Iphdr.disassemble(pkt[28..47])
        found = true if ref.dst == @target
      end

      @waiting = false if ip.src == @target

      hop_found(@hops.last, ip, icmp) if found
    end
  end

  def notify_writable
    if @waiting && !(@out_queue.empty?)
      hop = @out_queue.shift
      pkt = hop.pkt
      if  @hops.empty? ||
          (!(@hops.empty?) && hop.ttl != @hops.last.ttl)
        @hops << hop
      end
      sockaddr = Socket.sockaddr_in(0, hop.ip.dst)
      @io.send(pkt, 0, sockaddr)

      timeout = @settings.fetch('timeout')
      EM.add_timer(timeout) { hop_timeout }
    end
  end

  def unbind
  end

  def hop_found(hop, ip, icmp)
    hop.remote_ip = ip
    hop.remote_icmp = icmp

    if ip && icmp
      hop.found = Time.now.to_f

      if @settings.fetch "geoip_lookup"

        url = "http://freegeoip.net/json/#{ip.src}"

        page = open(url).read
        d = JSON.load page

        hop.location = [d["country_name"], d["region_name"], d["city"]].select do |s|
          s && !(s.empty?)
        end.join(", ").encode("utf-8")
      end
    end

    ttl = hop.ttl + 1
    tail = @hops.last(2)
    if  tail.size == 2 && tail.first.remote_ip == ip ||
        (ttl > (@settings.fetch("max_hops", 30) + 1))
      done = true
    else
      done = false
    end

    unless done
      if(cb = @settings.fetch "hop_callback")
        cb.call(hop)
      end
    end

    unless @waiting
      if @deferred
        @deferred.set_deferred_status :succeeded, @hops
        @deferred = nil
      end
      EM.stop
    else
      @out_queue << Hop.new(@target, ttl)
    end
  rescue
    detach
  end

  def hop_timeout *ign
    hop = @hops.last
    unless hop.found
      if hop.tries < @settings.fetch("max_tries")
        # retry
        @out_queue << hop
      else
        # give up and move forward
        hop_found(hop, nil, nil)
      end
    end
  end
end


def traceroute target, settings
  fd = Socket.new(Socket::AF_INET, Socket::SOCK_RAW, Socket::IPPROTO_ICMP)
  fd.setsockopt(Socket::IPPROTO_IP, Socket::IP_HDRINCL, 1)

  conn = EM.watch(fd, Handler, target, settings)

  conn.notify_readable = true
  conn.notify_writable = true

  unless settings["hop_callback"]
    conn.deferred.callback {|hop| puts hop }
  end
end


def main
  if Process.uid != 0
    puts "traceroute needs root privileges for the raw socket"
    exit(1)
  end

  defaults = {
    "hop_callback" => lambda {|hop| puts hop },
    "timeout" => 2,
    "max_tries" => 3,
    "max_hops" => 30,
    "geoip_lookup" => true
  }

  if ARGV.size < 1
    puts "Usage: #{$0} [options]"
    puts "#{$0}: Try --help for usage details."
    exit
  end

  opts = {}

  config = OptionParser.new

  config.on("-t [VAL]", "--timeout [VAL]") {|v| opts["timeout"] = v.to_i }
  config.on("-r [VAL]", "--tries [VAL]") {|v| opts["tries"] = v.to_i }
  config.on("-m [VAL]", "--max_hops [VAL]") {|v| opts["max_hops"] = v.to_i }
  config.on("-s", "--silent") { opts["silent"] = nil }
  config.on("-g", "--no-geoip") { opts["geoip_lookup"] = false }

  config.parse!(ARGV)
  target = ARGV.last[0] != "-" ? ARGV.pop : nil

  begin
    unless target
      raise OptionParser::InvalidArgument
    end
  rescue => ex
    puts ex.message
    exit(1)
  end

  settings = defaults.dup

  
  settings["timeout"] = opts["timeout"] if opts.include? "timeout"
  settings["max_tries"] = opts["tries"] if opts.include? "tries"
  settings["max_hops"] = opts["max_hops"] if opts.include? "max_hops"
  settings["hop_callback"] = opts["silent"] if opts.include? "silent"
  settings["geoip_lookup"] = opts["geoip_lookup"] if opts.include? "geoip_lookup"

  begin
    target = IPSocket.getaddress(target)
  rescue Exception => ex
    puts "Couldn't resolve #{target}: #{ex}"
    exit(1)
  end

  EM.run { traceroute(target, settings) }
end


if __FILE__ == $0
  main
end
