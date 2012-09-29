module EM::TracerouteHandler
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
    @out_queue << EM::Traceroute::Hop.new(@target, 1)
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
        ref =  Iphdr.disassemble(pkt[28..47])
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
      if  @hops.empty? || !(@hops.empty?) && hop.ttl != @hops.last.ttl
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
      @out_queue << EM::Traceroute::Hop.new(@target, ttl)
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
