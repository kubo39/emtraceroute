#!/usr/bin/env ruby
# -*- coding: utf-8 -*-
require 'rubygems'
require 'socket'
require 'eventmachine'
require 'optparse'

# extension for socket library
class Socket
  # ip address format to network byte order.
  def self.inet_aton ip
    return ip.split(/\./).map(&:to_i).pack("C*")
  end

  # network byte order to ip address format.
  def self.inet_ntoa n
    return n.unpack("C*").join "."
  end

  # host (unsigned char) byte order to network byte order.
  def self.htons id
    return [id].pack("s").unpack("n").first.to_i
  end
end

class Iphdr
  attr_accessor :version, :hlen, :tos, :id, :length, :frag,
   :ttl, :dst, :proto, :cksum, :src, :saddr, :daddr, :data
  def initialize(proto=Socket::IPPROTO_ICMP, src='0.0.0.0', dst=nil)
    @version = 4                    # バージョン番号
    @hlen = 5                       # ヘッダー長
    @tos = 0                        # サービス識別（優先順位や遅延を表す）
    @length = 20                    # IPデータグラム全体のバイト数
    @id = $$                        # 識別子(シーケンス番号)
    @frag = 0                       # フラグ(どのように配送するかの値)
    @ttl = 255                      # 最大ゲートウェイ数(通過可能なルータの数)
    @proto = proto                  # プロトコルの種類
    @cksum = 0                      # IPヘッダチェックサム(データの正しさを検証)
    @src = src                      # 送信元アドレス
    @saddr = Socket.inet_aton(src)  # 送信元IPアドレス
    @dst = dst || '0.0.0.0'         # 送信先アドレス
    @daddr = Socket.inet_aton(@dst) # 送信先IPアドレス
    @data = ''                      # データ部
  end

  def assemble
    header = [(@version & 0x0f) << 4 | (@hlen & 0x0f),
              @tos, @length + @data.size,
              Socket.htons(@id), @frag,
              @ttl, @proto
             ].pack('CCSSSCC')
    return header + "\000\000" + @saddr.to_s + @daddr.to_s + @data
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
    return ip
  end
end


# ICMP header を表すクラス
class Icmphdr
  attr_accessor :type, :code, :cksum, :id, :sequence, :data
  def initialize data=""
    @type = 8      # ICMPメッセージの種類(8はエコー要求)
    @code = 0      # コード(ここでは特に意味なし。穴埋め。)
    @cksum = 0     # ICMPメッセージ全体に対するチェックサム
    @id = $$       # 識別子
    @sequence = 0  # シーケンス番号(どの要求に対する応答かを判定)
    @data = data   # データ部
  end

  def assemble
    part1 = [@type, @code].pack('C*')
    part2 = [@id, @sequence].pack('n*')
    cksum = Icmphdr.checksum(part1 + "\000\000" + part2 + @data)
    cksum = [cksum].pack('n')
    return part1 + cksum + part2 + @data
  end

  def self.checksum data
    if data.size & 1 == 1
      data += '\0'
    end
    cksum = data.unpack("n*")[0..(data.size >> 1)].inject(&:+)
    cksum = (cksum >> 16) + (cksum & 0xffff)
    cksum += (cksum >> 16)
    cksum = (cksum & 0xffff) ^ 0xffff
    return cksum
  end

  def self.disassemble data
    icmp = Icmphdr.new
    pkt = data.unpack('CCnnn')
    icmp.type, icmp.code, icmp.cksum, icmp.id, icmp.sequence = pkt
    return icmp
  end
end


class Hop
  attr_accessor :found, :tries, :remote_ip, :remote_icmp,
  :ttl, :ip, :pkt, :icmp
  def initialize(target, ttl)
    @found = false
    @tries = 0
    @last_try = 0
    @remote_ip = nil
    @remote_icmp = nil
    @remote_host = nil

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
    @last_try = Time.now.to_i
    @pkt
  end

  def to_s
    if @found
      if @remote_host
        ip = ":: #{@remote_host}"
      else
        ip = ":: #{remote_ip.src}"
      end
      ping = "#{@found - @last_try}"
    else
      ip = "??"
      ping = "-"
    end

    return "#{@ttl}, #{ping}, #{ip}"
  end
end


module Handler
  def initialize target, settings
    @target = target
    @settings = settings
  end

  def post_init
    @hops = []
    @out_queue = []
    @waiting = true

    # send first probe packet
    @out_queue << Hop.new(@target, 1)
  end

  def notify_readable
    if !@waiting || @hops.empty?
      return
    end

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
        if ref.dst == @target
          found = true
        end
      end

      if ip.src == @target
        @waiting = false
      end

      if found
        hop_found(@hops.last, ip, icmp)
      end
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
      EM.add_timer(timeout) do
        hop_timeout
      end
    end
  end

  def unbind
    EM.stop
  end

  def hop_found(hop, ip, icmp)
    hop.remote_ip = ip
    hop.remote_icmp = icmp

    if ip && icmp
      hop.found = Time.now.to_i
    end

    ttl = hop.ttl + 1

    puts hop

    if @target == hop.remote_ip.src
      unbind
    end

    if @waiting
      @out_queue << Hop.new(@target, ttl.to_i)
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


class TracerouteProtocol
  def initialize(target, settings={})
    fd = Socket.new(Socket::AF_INET, Socket::SOCK_RAW, Socket::IPPROTO_ICMP)
    fd.setsockopt(Socket::IPPROTO_IP, Socket::IP_HDRINCL, 1)

    conn = EM.watch(fd, Handler, target, settings)

    conn.notify_readable = true
    conn.notify_writable = true
  end
end

def traceroute target, settings
  tr = TracerouteProtocol.new(target, settings)
end


def main
  if Process.uid != 0
    puts("traceroute needs root privileges for the raw socket")
    exit(1)
  end

  defaults = {
    "timeout" => 2,
    "max_tries" => 3,
  }

  opts = {}

  config = OptionParser.new
  config.on("-t VAL", "--timeout VAL") do |v|
    opts["timeout"] = v.to_i
  end

  config.on("-r VAL", "--tries VAL") do |v|
    opts["tries"] = v.to_i
  end

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

  if opts.include?("timeout")
    settings["timeout"] = opts["timeout"]
  end

  if opts.include?("tries")
    settings["max_tries"] = opts["tries"]
  end

  EM.run do
    traceroute(target, settings)
  end
end

if __FILE__ == $0
  main
end
