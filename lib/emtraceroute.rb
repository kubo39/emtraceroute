# -*- coding: utf-8 -*-
require 'socket'
require 'eventmachine'
require 'open-uri'
require 'json'

require_relative 'emtraceroute/version'
require_relative 'emtraceroute/ext/socket'
require_relative 'emtraceroute/ip'
require_relative 'emtraceroute/icmp'
require_relative 'emtraceroute/hop'
require_relative 'emtraceroute/handler'


module EM::Traceroute
  def self.start_trace target, settings
    fd = Socket.new(Socket::AF_INET, Socket::SOCK_RAW, Socket::IPPROTO_ICMP)
    fd.setsockopt(Socket::IPPROTO_IP, Socket::IP_HDRINCL, 1)

    conn = EM.watch(fd, EM::TracerouteHandler, target, settings)
    conn.notify_readable = true
    conn.notify_writable = true

    unless settings["hop_callback"]
      conn.deferred.callback {|hop| puts hop }
    end
  end
end
