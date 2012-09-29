module EM::Traceroute
  class Hop
    attr_accessor :found, :tries, :remote_ip, :remote_icmp, :location, :ttl, :ip, :pkt, :icmp
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
end
