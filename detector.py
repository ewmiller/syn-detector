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

  # helper method to determine if this address is suspected of SYN scanning
  def is_suspect(self):

    # try/catch to handle case where syn_ack_received is 0
    try:
      res = self.syn_sent / self.syn_ack_received
      break
    except ZeroDivisionError:
      if syn_sent >= 3:
        return True
      else:
        return False

    # normal case: figure out if this address sent too many SYN requests compared to the SYN + ACK requests it received
    if res >= 3:
      return True
    else:
      return False

# helper method for processPacket
def countPacket(addr, indicator):
  found = False
  for x in address_list:
    if x.ip_address == addr:
      found = True
      x.increment(indicator)
  if not found:
    new_addr = Address(addr)
    new_addr.increment(indicator)
    address_list.append(new_addr)

# lambda function passed to scapy.sniff
def processPacket(packet):
  global packet_count
  global SYN
  global SYN_ACK

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


print "Reading packets from file..."
scapy.sniff(offline=arg, prn=processPacket, lfilter=lambda x: x.haslayer("TCP"))

print "Any addresses displayed below are suspected of SYN scanning:"
print "------"
for addr in address_list:
  if addr.is_suspect:
    print addr.ip_address
print "------"
print "Analysis complete."
