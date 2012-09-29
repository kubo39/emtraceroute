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
