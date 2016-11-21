import scapy.all as scapy
import sys

# Goal: read .pcap file packet-by-packet
# for each packet, check if it's a SYN request
# if so, store source IP address in array and make its SYN count 1
# if it appears again, increment its SYN count
# ignore other packets
# once finished, look through the array for any IPs that satisfy the suspicion requirements
# print these to the console

# counter for total packets processed, and an array to hold unique IPs
packetCount = 0
ipArray = [[]]
arg = sys.argv[1]

# lambda function passed to scapy.sniff
def processPacket(packet):
  if(packet.haslayer("TCP")):
    return packet.show()



# importing the whole pcap file takes a while
# use sniff(offline="...", prn=customFunction) to process them individually as they come in
scapy.sniff(offline=arg, prn=processPacket)
