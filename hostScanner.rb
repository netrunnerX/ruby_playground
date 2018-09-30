#!/usr/bin/env ruby

require 'packetgen'
require 'packetgen/config'
require 'ip_admin'
require 'socket'

def getIpLastDigits(anIp)
    dotIndex = anIp.rindex('.')
    digits = anIp[dotIndex+1..-1].to_i
    return digits
end

def getSortedAliveIps(ipHash)
    ipsArray = []

    ipHash.sort { |a,b| a[1] <=> b[1] }.each { |ipHashElem|
        ipsArray.push(ipHashElem[0])
    }
    return ipsArray
end

if $0 == __FILE__

    config = PacketGen::Config.instance
    iface = config.default_iface
    ip = config.ipaddr
    mac = config.hwaddr
    gateway = gw = `ip route show`[/default.*/][/\d+\.\d+\.\d+\.\d+/]

    #Getting the netmask
    netmask = ""
    Socket.getifaddrs.each { | ifaddr |
        if ifaddr.addr.to_s == Addrinfo.ip(ip).to_s
            netmask = ifaddr.netmask.ip_unpack.shift
            break
        end
    }

    #Build a CIDR
    cidr_mask = IPAdmin.unpack_ip_netmask(IPAdmin.pack_ip_netmask(netmask))
    cidr = IPAdmin::CIDR.new("#{ip}/#{cidr_mask}")

    #Getting all subnet IPs
    ipsToScan = cidr.enumerate
    #Get rid of base subnet IP, broadcast IP, and our own IP
    ipsToScan.pop
    ipsToScan.shift
    ipsToScan.delete(ip)

    puts "---------Device Information---------"
    puts "Name: #{iface}"
    puts "IP: #{ip}"
    puts "Gateway: #{gateway}"
    puts "Netmask: #{netmask}"
    puts "MAC: #{mac}"
    puts "------------------------------------"
    timeoutSecs = 20
    puts "Scanning... (this takes #{timeoutSecs} seconds)"
    #TODO - Config ready, it's time to scan

    thread = Thread.new {
        Thread.current['packets'] = PacketGen.capture(iface: iface, 
                                                    promisc: true, 
                                                    filter: "arp dst #{ip}", 
                                                    timeout: timeoutSecs)
    }

    ipsToScan.each { | targetIp |

        #Spam 5 ARP packets
        #5.times do
            PacketGen::Packet.gen('Eth', src: mac, dst: 'ff:ff:ff:ff:ff:ff')
                            .add('ARP', spa: ip, 
                                        tpa: targetIp, 
                                        sha: mac, 
                                        tha: 'ff:ff:ff:ff:ff:ff', 
                                        op: 'request')
            .to_w(iface)
        #end
    }

    thread.join
    packets = thread['packets']

    aliveIps = Hash.new
    packets.each { | packet |
        aliveIps[packet.arp.spa] = getIpLastDigits(packet.arp.spa)
    }

    getSortedAliveIps(aliveIps).each { |aliveIp|
        puts "#{aliveIp} is up"
    }

end