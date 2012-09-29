class Icmphdr
  # This represents an ICMP packet header.
  #
  # Icmphdr#assemble packages the packet
  # Imphdr.checsum calc checksum
  # Icmphdr.disassemble disassembles the packet
  #
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
