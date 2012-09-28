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
