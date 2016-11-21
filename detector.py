import scapy.all as scapy
import sys

# Goal: read .pcap file packet-by-packet
# for each packet, check if it's a SYN request
# if so, store source IP address in array and make its SYN count 1
# if it appears again, increment its SYN count
# ignore other packets
# once finished, look through the array for any IPs that satisfy the suspicion requirements
# print these to the console

# counter for total packets processed, and a list to hold unique IPs and their 
packetCount = 0
ipArray = []
arg = sys.argv[1]

# helper method for processPacket
def countPacket(packet):
  print "packet counted"

# lambda function passed to scapy.sniff
def processPacket(packet):
  global packetCount
  packetCount+=1
  print packetCount

  if(packet.haslayer("TCP")):
    # grab flags from the packet
    flags = packet["TCP"].flags

    # do a bitwise AND to see which flag is set
    SYN = 0x02
    SYNACK = 0x12
    if flags & SYN:
      print "SYN detected. Source: %s, Dest: %s" % (packet["IP"].src, packet["IP"].dst)
    elif flags & SYNACK:
      print "SYN-ACK detected. Source: %s, Dest: %s" % (packet["IP"].src, packet["IP"].dst)

# importing the whole pcap file takes a while
# use sniff(offline="...", prn=customFunction) to process them individually as they come in
scapy.sniff(offline=arg, prn=processPacket)
