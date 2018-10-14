#!/usr/bin/env ruby

#Elisa script
#This beauty can scan the local network and perform ARP spoofing

require_relative 'elisa_core'

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
        else
            puts "\nInvalid option\n"
            return nil
        end
    else
        puts "\nInvalid option\n"
        return nil
    end
    
end


puts "-----------  Elisa  ------------\n"
puts "Your wishes are my commands\n\n"

core = ElisaCore.new

core.printDeviceInfo

core.startScan

option = -1
while option != "0" do
    puts "\nTarget selected: " + (core.targetIp.nil? ? "None\n" : "#{core.targetIp}\n")

    puts "\n----------- OPTIONS -----------\n"
    puts "1-Select a target from scanned IPs\n"
    puts "2-Scan again\n"
    puts "3-Add target to ARP spoofer\n"
    puts "4-Start ARP spoofing\n"
    puts "5-Check active spoofings\n"
    puts "6-Stop ARP spoofing\n"
    puts "0-Exit\n"

    option = gets
    option = option.chomp

    case option
    when "0"
        begin
            core.stopSpoofing
        rescue => exception
            
        end
        puts "\nSee you!\n"
    when "1"
        core.targetIp = selectTarget(core.getAliveIpsArray)
    when "2"
        core.startScan
    when "3"
        if core.targetIp.nil?
            puts "\nFirst you must select a target\n"
        else
            core.addTarget
            puts "\nTarget added!"
        end
    when "4"
        core.startSpoofing
        puts "\nAPR spoofing started!"
    when "5"
        core.checkActiveSpoofings
    when "6"
        core.stopSpoofing
        puts "\nAPR spoofing stoped!"
    else
        puts "\nInvalid option\n"
    end

end

