import scapy.all as scapy
import sys

# Goal: read .pcap file packet-by-packet
# for each packet, check if it's a SYN request
# if so, store source IP address in array and make its SYN count 1
# if it appears again, increment its SYN count
# ignore other packets
# once finished, look through the array for any IPs that satisfy the suspicion requirements
# print these to the console

packet_count = 0
address_list = []
arg = sys.argv[1]
SYN = 0x02
SYN_ACK = 0x12

class Address:
  global SYN
  global SYN_ACK
  ip_address = 0
  syn_sent = 0
  syn_ack_received = 0

  def __init__(self, ip):
    self.ip_address = ip

  def increment(self, indicator):
    if indicator == SYN:
      self.syn_sent+=1
    elif indicator == SYN_ACK:
      self.syn_ack_received+=1

# helper method for processPacket
def countPacket(addr, indicator):
  found = False
  for x in address_list:
    if x.ip_address == addr:
      found = true
      x.increment(indicator)
  if not found:
    new_addr = Address(addr)
    new_addr.increment(indicator)

# lambda function passed to scapy.sniff
def processPacket(packet):
  global packet_count
  global SYN
  global SYN_ACK

#  packet_count+=1
#  print packet_count

  if(packet.haslayer("TCP")):
    # grab flags from the packet
    flags = packet["TCP"].flags

    # do a bitwise AND to see which flag is set
    # if SYN or SYN-ACK, respond accordingly
    SYN = 0x02
    SYNACK = 0x12
    if flags & SYN:
      print "SYN detected. Source: %s, Dest: %s" % (packet["IP"].src, packet["IP"].dst)
      countPacket(packet["IP"].src, SYN)
    elif flags & SYN_ACK:
      print "SYN-ACK detected. Source: %s, Dest: %s" % (packet["IP"].src, packet["IP"].dst)
      countPacket(packet["IP"].dst, SYN_ACK)

# importing the whole pcap file takes a while
# use sniff(offline="...", prn=customFunction) to process them individually as they come in
print "Reading packets from file..."
pkts = scapy.rdpcap(arg)
for pk in pkts:
  processPacket(pk)
